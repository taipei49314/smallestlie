"""SOURCE_ONLY / NOT_RUN: actual ordinary child pipes and finite retention."""
from __future__ import annotations
import os
from pathlib import Path
import signal
import subprocess
import sys
from workloads.m12_adjudication_verify.pipe_capture import PipeCapture,secondary,first
from workloads.m12_adjudication_verify.output_bound import OutputBudget,OutputRefusal,preserve_refusal,refusal_diagnostic,finite_deadline

_UNCLOSED_UNASSIGNED=[]  # Failed native close: retain original objects, no repair claim.


class Runner:
    def __init__(self,root,out,env,budget,output=None):
        self.root,self.out,self.env,self.budget=root,out,env,budget
        self.output=output if output is not None else OutputBudget(out,budget.deadline,create=True,clock=budget.clock)
        self.steps=[]
    def _spawn(self,command,*,environment):
        kwargs={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {'start_new_session':True}
        return subprocess.Popen(command,cwd=self.root,env=environment,stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,**kwargs)
    def _capture(self,process,name,*,output):
        return PipeCapture(process,output,{stream:self.out/(name+'.'+stream) for stream in ('stdout','stderr')},self.budget)
    def _stage(self,name,deadline):
        if self.output.entry_deadline!=self.budget.deadline: raise OutputRefusal('entry/output original deadline mismatch')
        owner=self.output.for_stage(name,deadline)
        environment=dict(self.env)
        environment.update(SL_OUTPUT_ROOT=str(owner.out),SL_OUTPUT_DEADLINE=repr(owner.entry_deadline),
            SL_OUTPUT_STAGE=owner.stage_name,SL_OUTPUT_STAGE_DEADLINE=repr(owner.deadline))
        if owner.work is not None: environment['SL_OUTPUT_WORK']=str(owner.work)
        return owner,environment
    def _close_unassigned(self,process,sinks):
        """Only before a capture exists/any start attempt; close independently."""
        primary=None; holder={'process':process,'sinks':dict(sinks)}
        _UNCLOSED_UNASSIGNED.append(holder)  # Before any secondary cleanup can fail.
        for stream in ('stdout','stderr'):
            try:
                sink=sinks.get(stream)
                if sink is not None: sink.close()
            except BaseException as error: primary=first(primary,error)
            try:
                pipe=None if process is None else getattr(process,stream)
                if pipe is not None: pipe.close()
            except BaseException as error: primary=first(primary,error)
        if primary is not None: raise primary
        _UNCLOSED_UNASSIGNED.remove(holder)
    def run(self,name,command,cap,*,final=False):
        began=self.budget.clock(); process=None; capture=None; primary=None; sinks={}
        record=dict(name=name,command=command,exit_code=2,timed_out=False,started=False,
                    child_return_observed=False,child_return_code=None,refusal_diagnostic=None,
                    execution_stage=None,stage_absolute_deadline=None,
                    entry_remaining_before=round(self.budget.remaining(),3))
        try:
            if not finite_deadline(cap): raise OutputRefusal('invalid child stage cap or timeout')
            timeout=self.budget.timeout(cap,final=final)
            if not finite_deadline(timeout) or timeout>cap: raise OutputRefusal('invalid child stage cap or timeout')
            deadline=min(began+cap,self.budget.clock()+timeout,self.budget.deadline)
            if deadline<=self.budget.clock(): raise OutputRefusal('deadline before child')
            stage_output,environment=self._stage(name,deadline)
            record.update(execution_stage=stage_output.stage_name,stage_absolute_deadline=stage_output.deadline)
            # Opening/charging both sinks before spawn is required. A failed
            # reader startup cannot expose an unretained child stream.
            for stream in ('stdout','stderr'): sinks[stream]=stage_output.open(self.out/(name+'.'+stream))
            stage_output.ensure_live()
            process=self._spawn(command,environment=environment)
            record.update(started=True,pid=process.pid,allocated_seconds=deadline-began)
            if stage_output._now()>=deadline: raise subprocess.TimeoutExpired(command,cap)
            capture=self._capture(process,name,output=stage_output); capture.sinks=sinks; capture.start()
            actual_return=capture.wait(deadline)
            if type(actual_return) is not int: raise OutputRefusal('unknown child return observation')
            record.update(exit_code=actual_return,child_return_observed=True,child_return_code=actual_return)
        except BaseException as error:
            primary=error
            if isinstance(error,subprocess.TimeoutExpired): record.update(exit_code=124,timed_out=True)
            record['error_type']=type(error).__name__
            record['refusal_diagnostic']=refusal_diagnostic(primary)
            if type(error).__name__=='BudgetExhausted': record['budget_exhausted']=True
            if process is not None:
                try: record['cleanup']=self._close_child(process)
                except BaseException as later: secondary(primary,later)
            if capture is not None:
                try: capture.finish()
                except BaseException as later: secondary(primary,later)
            else:
                try: self._close_unassigned(process,sinks)
                except BaseException as later: secondary(primary,later)
        finally:
            record['elapsed_seconds']=round(self.budget.clock()-began,3)
            record['entry_remaining_after']=round(self.budget.remaining(),3)
            record['streams']={} if capture is None else capture.rows
            record['output_complete']=primary is None and capture is not None and capture.complete()
            for stream in ('stdout','stderr'):
                record[stream+'_sha256']=None if capture is None else capture.rows[stream]['sha256']
            self.steps.append(record)
        if primary is not None:
            try: preserve_refusal(self.out,dict(schema_version='smallestlie-output-bound-v1',
                primary_type=type(primary).__name__,refusal_diagnostic=refusal_diagnostic(primary),step=record))
            except BaseException as later: secondary(primary,later)
            if not isinstance(primary,subprocess.TimeoutExpired): raise primary
        return record['exit_code']
    def _close_child(self,process):
        state=dict(tree_kill='UNCONFIRMED',parent_reaped=False,cleanup_return_observed=False,cleanup_return_code=None)
        primary=None
        try:
            if sys.platform=='win32':
                root=next((value for key,value in self.env.items() if key.upper()=='SYSTEMROOT'),None)
                if not root: raise OSError('no SystemRoot for fixed taskkill')
                timeout=self.budget.timeout(15,closing=True)
                if not finite_deadline(timeout) or timeout>15: raise OutputRefusal('invalid child stage cap or timeout')
                deadline=min(self.budget.deadline,self.budget.clock()+timeout)
                output,environment=self._stage('child_cleanup',deadline)
                output.ensure_live()
                killer=self._spawn([str(Path(root)/'System32/taskkill.exe'),'/PID',str(process.pid),'/T','/F'],environment=environment)
                capture=None; killer_primary=None
                try:
                    output.ensure_live()
                    capture=self._capture(killer,'pid-'+str(process.pid)+'-taskkill',output=output)
                    capture.start()
                    code=capture.wait(deadline)
                    state['tree_kill_exit']=code; state['taskkill_streams']=capture.rows
                    if code==0: state['tree_kill']='COMMAND_SUCCEEDED'
                except BaseException as error:
                    killer_primary=error
                finally:
                    alive=None
                    try: alive=killer.poll()
                    except BaseException as later: killer_primary=first(killer_primary,later)
                    try:
                        if alive is None: killer.kill()
                    except BaseException as later: killer_primary=first(killer_primary,later)
                    try:
                        if capture is not None: capture.finish()
                        else: self._close_unassigned(killer,{})
                    except BaseException as later: killer_primary=first(killer_primary,later)
                if killer_primary is not None: raise killer_primary
            else:
                os.killpg(process.pid,signal.SIGKILL); state['tree_kill']='COMMAND_SUCCEEDED'
        except BaseException as error: primary=error; state['error_type']=type(error).__name__
        alive=None
        try: alive=process.poll()
        except BaseException as later: primary=first(primary,later)
        try:
            if alive is None: process.kill()
        except BaseException as later: primary=first(primary,later)
        try:
            timeout=self.budget.timeout(5,closing=True)
            if not finite_deadline(timeout) or timeout>5: raise OutputRefusal('invalid child stage cap or timeout')
            deadline=min(self.budget.deadline,self.budget.clock()+timeout)
            if not finite_deadline(timeout) or deadline<=self.budget.clock(): raise OutputRefusal('late cleanup return')
            actual_return=process.wait(timeout=max(0,deadline-self.budget.clock()))
            state['parent_reaped']=True
            if type(actual_return) is int:
                state.update(cleanup_return_observed=True,cleanup_return_code=actual_return)
            else: raise OutputRefusal('unknown child return observation')
            if self.budget.clock()>=deadline: raise OutputRefusal('late cleanup return')
        except BaseException as later: primary=first(primary,later)
        # Command return/reap do not prove native descendant/writer closure.
        if primary is not None: state['closure_error_type']=type(primary).__name__
        return state
