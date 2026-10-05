"""SOURCE_ONLY / NOT_RUN: finite prefixes and explicit native-reader ownership."""
from __future__ import annotations
import base64
import hashlib
import subprocess
import threading
from workloads.m12_adjudication_verify.output_bound import OutputRefusal,PAGE

_UNCLOSED=[]  # Retain BEFORE start/join/cleanup can fail; no native closure claim.


def secondary(primary,error):
    try: BaseException.add_note(primary,'secondary pipe closure: '+type(error).__name__)
    except BaseException: pass


def first(primary,error):
    if primary is None: return error
    if error is not primary: secondary(primary,error)
    return primary


class PipeCapture:
    def __init__(self,process,output,paths,budget):
        self.process,self.output,self.paths,self.budget=process,output,paths,budget
        self.rows={name:dict(bytes=0,sha256=None,eof=False,writer_closed=False,pipe_closed=False,
                            unwritten_page_base64=None,reader_start='NOT_ATTEMPTED',
                            reader_entered=False,reader_finished=False,reader_joined=False)
                   for name in ('stdout','stderr')}
        self.owners={name:dict(pipe=None,associated=False,thread=None,attempted=False,returned=False,
                               entered=threading.Event(),done=threading.Event())
                     for name in self.rows}
        self.errors=[]; self.threads=[]; self.pipes=[]; self.sinks={}
    def _retain(self):
        if self not in _UNCLOSED: _UNCLOSED.append(self)
    def _reader(self,name,pipe):
        owner=self.owners[name]; row=self.rows[name]
        # This is an actual target entry, unlike start return/exception/ident.
        owner['pipe']=pipe; owner['associated']=True; owner['entered'].set(); row['reader_entered']=True
        writer=self.sinks.get(name); primary=None; held=b''; sha=None
        try:
            if writer is None: writer=self.output.open(self.paths[name])
            sha=hashlib.sha256()
            while True:
                window=min(PAGE,writer.cap-writer.written)
                if window<=0: raise OutputRefusal('stream logical cap plus actual sentinel')
                writer.reserve_read(window)  # Before every actual native read; no refund.
                held=pipe.read(window)
                if type(held) is not bytes: raise OutputRefusal('unknown actual pipe observation')
                actual_eof=not held
                writer.write_observed(held); sha.update(held); row['bytes']+=len(held); held=b''
                if writer.written==writer.cap: raise OutputRefusal('stream logical cap plus actual sentinel')
                if writer.read_credit: raise OutputRefusal('unconsumed capture read credit')
                if actual_eof: row['eof']=True; break
        except BaseException as error:
            primary=error; self.errors.append(primary)
        finally:
            try:
                if held: row['unwritten_page_base64']=base64.b64encode(held).decode('ascii')
            except BaseException as error: primary=first(primary,error)
            try:
                if writer is not None: writer.close(); row['writer_closed']=writer.closed
            except BaseException as error: primary=first(primary,error)
            try: pipe.close(); row['pipe_closed']=True
            except BaseException as error: primary=first(primary,error)
            try:
                row['sha256']=sha.hexdigest() if row['writer_closed'] and primary is None else None
                row['failure_type']=None if primary is None else type(primary).__name__
                row['written_bytes']=0 if writer is None else writer.written
            except BaseException as error: primary=first(primary,error)
            if primary is not None and all(error is not primary for error in self.errors): self.errors.append(primary)
            row['reader_finished']=True; owner['done'].set()
    def start(self):
        # Acquire both associations before any start, so the second unattempted
        # channel can be closed even if the first attempt becomes uncertain.
        for name,owner in self.owners.items():
            owner['pipe']=getattr(self.process,name); owner['associated']=True; self.pipes.append(owner['pipe'])
        for name,owner in self.owners.items():
            thread=threading.Thread(target=self._reader,args=(name,owner['pipe']),daemon=True)
            owner['thread']=thread; self.threads.append(thread)
            self._retain()  # Failure here precedes attempt; resource stays unassigned.
            owner['attempted']=True; self.rows[name]['reader_start']='ATTEMPTED_UNCONFIRMED'
            thread.start()  # May raise AFTER OS start. Never downgrade this state.
            owner['returned']=True; self.rows[name]['reader_start']='RETURNED'
    def complete(self):
        return not self.errors and all(row['eof'] and row['writer_closed'] and row['pipe_closed']
                                      and row['reader_entered'] and row['reader_finished']
                                      and row['reader_joined'] for row in self.rows.values())
    def wait(self,deadline):
        while self.process.poll() is None:
            if self.errors: raise self.errors[0]
            left=min(deadline-self.budget.clock(),self.budget.remaining())
            if left<=0: raise subprocess.TimeoutExpired(self.process.args,max(0,left))
            try: self.process.wait(timeout=min(.05,left))
            except subprocess.TimeoutExpired: pass
        self.finish(deadline)
        if self.errors: raise self.errors[0]
        if self.budget.clock()>=deadline: raise subprocess.TimeoutExpired(self.process.args,0)
        if not self.complete(): raise OutputRefusal('pipe completeness/closure unconfirmed')
        return self.process.returncode
    def finish(self,deadline=None):
        # Keep all holders before any clock, join, or secondary close failure.
        self._retain(); primary=None; end=None
        try:
            end=min(self.budget.deadline,self.budget.clock()+5)
            if deadline is not None: end=min(end,deadline)
        except BaseException as error: primary=first(primary,error)
        for name,owner in self.owners.items():
            row=self.rows[name]
            if not owner['attempted']:
                # No start attempted: neither sink nor pipe was transferred.
                try:
                    writer=self.sinks.get(name)
                    if writer is not None: writer.close(); row['writer_closed']=writer.closed
                except BaseException as error: primary=first(primary,error)
                try:
                    pipe=owner['pipe']
                    if not owner['associated'] and self.process is not None:
                        pipe=getattr(self.process,name); owner['pipe']=pipe; owner['associated']=True
                    if pipe is not None: pipe.close(); row['pipe_closed']=True
                except BaseException as error: primary=first(primary,error)
                continue
            # An exception without actual target entry gives no safe joinable
            # association. ident/is_alive alone cannot resolve that uncertainty.
            if not (owner['returned'] or owner['entered'].is_set()): continue
            row['reader_joined']=False
            try:
                left=0 if end is None else max(0,end-self.budget.clock())
                owner['thread'].join(timeout=left)
                row['reader_joined']=owner['done'].is_set() and not owner['thread'].is_alive()
            except BaseException as error: primary=first(primary,error)
        closed=all((self.rows[name]['reader_joined'] and self.rows[name]['writer_closed']
                    and self.rows[name]['pipe_closed']) if owner['attempted'] else
                   ((name not in self.sinks or self.rows[name]['writer_closed'])
                    and owner['associated'] and (owner['pipe'] is None or self.rows[name]['pipe_closed']))
                   for name,owner in self.owners.items())
        if not closed:
            primary=first(primary,OutputRefusal('native pipe reader/resource closure UNCONFIRMED; holder retained'))
        elif self in _UNCLOSED:
            _UNCLOSED.remove(self)
        if primary is not None: raise primary
