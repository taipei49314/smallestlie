"""SOURCE_ONLY / NOT_RUN: actual quota/writer/pipe/genuine JUnit contracts."""
import io
from pathlib import Path
from types import SimpleNamespace
import time
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workloads.m12_adjudication_verify import output_bound as bound
from workloads.m12_adjudication_verify import pipe_capture as pipes


def budget(root): return bound.OutputBudget(root,time.monotonic()+120,create=True)


def _fixture_dispose_attempts(output):
    # Only after this fixture observed its own exact real acquire/release/join.
    # No production reset method and no .locked() closure inference.
    for attempt in list(bound._UNCLOSED_MUTEX):
        if attempt.custody is output._mutex_custody: bound._UNCLOSED_MUTEX.remove(attempt)


def test_per_file_refuses_before_excess_and_preserves_original_calls(tmp_path,monkeypatch):
    with monkeypatch.context() as fault:
        fault.setitem(bound.CAPS,'requirements.txt',3)
        output=budget(tmp_path); stream=output.open(tmp_path/'requirements.txt')
        stream.write(b'abc'); before=output.path.read_bytes()
        with pytest.raises(bound.OutputRefusal) as caught: stream.write(b'd')
        assert bound.refusal_diagnostic(caught.value)==dict(reason_code='FILE_CAP',operation='writer',stage='write')
        stream.close()
        assert (tmp_path/'requirements.txt').read_bytes()==b'abc'
        assert output.path.read_bytes()==before  # Excess attempt never gains credit.


def test_aggregate_prepaid_read_refusal_happens_before_pipe_read(tmp_path,monkeypatch):
    with monkeypatch.context() as fault:
        fault.setattr(bound,'TOTAL',3*bound.STATE.size+3)
        fault.setattr(pipes,'PAGE',4)
        output=budget(tmp_path)
        class Delivered(io.BytesIO):
            reads=0
            def read(self,n): self.reads+=1; return super().read(n)
        stream=Delivered(b'abcdefgh')
        capture=pipes.PipeCapture(None,output,{'stdout':tmp_path/'focused.stdout'},SimpleNamespace())
        capture._reader('stdout',stream)
        assert stream.reads==0 and isinstance(capture.errors[0],bound.OutputRefusal)
        assert capture.rows['stdout']['refusal_diagnostic']['reason_code']=='AGGREGATE_QUOTA'
        assert (tmp_path/'focused.stdout').read_bytes()==b''
        assert capture.rows['stdout']['eof'] is False


def test_fragmented_actual_sentinel_is_retained_and_not_complete(tmp_path,monkeypatch):
    with monkeypatch.context() as fault:
        fault.setitem(bound.CAPS,'focused.stdout',5)
        fault.setattr(pipes,'PAGE',4)
        output=budget(tmp_path)
        capture=pipes.PipeCapture(None,output,{'stdout':tmp_path/'focused.stdout'},SimpleNamespace())
        capture._reader('stdout',io.BytesIO(b'abcdef'))
        assert (tmp_path/'focused.stdout').read_bytes()==b'abcde'
        assert capture.rows['stdout']['written_bytes']==5
        assert capture.rows['stdout']['sha256'] is None
        assert capture.rows['stdout']['eof'] is False
        assert isinstance(capture.errors[0],bound.OutputRefusal)


def test_unused_receive_window_stays_charged_and_eof_is_actual(tmp_path,monkeypatch):
    with monkeypatch.context() as fault:
        fault.setattr(pipes,'PAGE',4)
        output=budget(tmp_path)
        capture=pipes.PipeCapture(None,output,{'stdout':tmp_path/'focused.stdout'},SimpleNamespace())
        capture._reader('stdout',io.BytesIO(b'x'))
        assert not capture.errors and capture.rows['stdout']['eof']
        assert capture.rows['stdout']['writer_closed']
        _,charged,files,seq,_=bound.STATE.unpack(output.path.read_bytes())
        assert charged==4*bound.STATE.size+8 and files==2 and seq==3
        assert (tmp_path/'focused.stdout').read_bytes()==b'x'


def test_actual_short_write_retains_prefix_and_primary_survives_close(tmp_path,monkeypatch):
    output=budget(tmp_path); writer=output.open(tmp_path/'requirements.txt'); original=writer.stream
    class FailingSink:
        def write(self,raw): return original.write(raw[:-1])
        def flush(self): return original.flush()
        def fileno(self): return original.fileno()
        def close(self): original.close(); raise OSError('secondary native close')
    writer.stream=FailingSink()
    with pytest.raises(bound.OutputRefusal) as caught:
        with writer: writer.write(b'abcdef')
    assert writer.written==5 and (tmp_path/'requirements.txt').read_bytes()==b'abcde'
    assert 'short output write' in str(caught.value)
    assert bound.refusal_diagnostic(caught.value)['reason_code']=='PAYLOAD_SHORT_WRITE'
    assert any('OSError' in note for note in caught.value.__notes__)


def test_ledger_partial_or_corrupt_blocks_payload_and_retains_existing_prefix(tmp_path):
    output=budget(tmp_path); writer=output.open(tmp_path/'requirements.txt'); writer.write(b'prefix')
    output.path.write_bytes(b'partial')  # Synthetic fault; never a production repair.
    with pytest.raises(bound.OutputRefusal): writer.write(b'extra')
    writer.close(); assert (tmp_path/'requirements.txt').read_bytes()==b'prefix'


def test_late_real_writer_close_is_refusal_after_actual_prefix(tmp_path):
    now=[0.0]; output=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    writer=output.open(tmp_path/'requirements.txt'); writer.write(b'prefix'); now[0]=10
    with pytest.raises(bound.OutputRefusal,match='late') as caught: writer.close()
    assert bound.refusal_diagnostic(caught.value)==dict(reason_code='LATE_CLOSE_IO',operation='writer',stage='close')
    assert writer.closed and (tmp_path/'requirements.txt').read_bytes()==b'prefix'


def test_genuine_junit_bound_is_one_instance_and_keeps_original_provider(tmp_path,monkeypatch):
    from _pytest.config import PytestPluginManager
    from _pytest import junitxml
    original=junitxml.LogXML.pytest_sessionfinish
    owner=junitxml.LogXML(str(tmp_path/'focused.xml'),None)
    pm=PytestPluginManager(); pm.register(owner)
    config=SimpleNamespace(stash={junitxml.xml_key:owner},pluginmanager=pm)
    output=budget(tmp_path); bound.bind_junit(config,output)
    assert junitxml.LogXML.pytest_sessionfinish is original
    assert 'open' not in original.__globals__  # Builtins and module not monkeypatched.
    owner.pytest_sessionstart(); owner.pytest_sessionfinish()
    assert (tmp_path/'focused.xml').read_bytes().startswith(b'<?xml')
    # The same genuine function now meets a real finite writer boundary.
    other=junitxml.LogXML(str(tmp_path/'partition.xml'),None); pm.register(other)
    with monkeypatch.context() as fault:
        fault.setitem(bound.CAPS,'partition.xml',40)
        config.stash[junitxml.xml_key]=other; bound.bind_junit(config,output); other.pytest_sessionstart()
        with pytest.raises(bound.OutputRefusal): other.pytest_sessionfinish()
        assert len((tmp_path/'partition.xml').read_bytes())<=40
        assert junitxml.LogXML.pytest_sessionfinish is original


def test_whole_physical_disk_claim_is_explicitly_refused():
    with pytest.raises(bound.OutputRefusal,match='WHOLE_PHYSICAL_DISK_NOT_ENFORCED'):
        bound.refuse_whole_physical_disk()


@pytest.mark.parametrize('fault_at', ('seek', 'unlock'))
@pytest.mark.parametrize('earlier_primary', (False, True))
def test_charge_cleanup_attempts_close_and_mutex_release_after_unlock_fault(tmp_path,monkeypatch,fault_at,earlier_primary):
    output=budget(tmp_path); opened=[]; original_open=Path.open
    native_fault=OSError('synthetic unlock/seek'); write_primary=OSError('original ledger write')
    close_fault=OSError('secondary close'); release_fault=OSError('secondary release')
    class Ledger:
        def __init__(self,raw): self.raw=raw; self.seeks=0; self.close_attempted=False
        def seek(self,*args):
            self.seeks+=1
            if fault_at=='seek' and self.seeks==4: raise native_fault
            return self.raw.seek(*args)
        def read(self,*args): return self.raw.read(*args)
        def write(self,raw):
            if earlier_primary: raise write_primary
            return self.raw.write(raw)
        def fileno(self): return self.raw.fileno()
        def close(self):
            self.close_attempted=True; self.raw.close()
            if earlier_primary: raise close_fault
    def opened_ledger(path,*args,**kwargs):
        raw=original_open(path,*args,**kwargs)
        if path==output.path and args and args[0]=='r+b':
            stream=Ledger(raw); opened.append(stream); return stream
        return raw
    mutex=output.mutex; released=[]
    def observed_release(actual):
        assert actual is mutex
        actual.release(); released.append(actual)
        if earlier_primary: raise release_fault
    try:
        with monkeypatch.context() as fault:
            fault.setattr(Path,'open',opened_ledger)
            fault.setattr(bound,'_release_output_mutex',observed_release)
            if fault_at=='unlock':
                def refused_unlock(stream): raise native_fault
                fault.setattr(bound,'_unlock_output_stream',refused_unlock)
            with pytest.raises(OSError) as caught: output.charge(1)
            assert caught.value is (write_primary if earlier_primary else native_fault)
            assert opened[0].close_attempted and opened[0].raw.closed
            assert released==[mutex] and not mutex.locked()
            if earlier_primary:
                assert sum('OSError' in note for note in caught.value.__notes__)==3  # Unlock, close, release all attempted.
    finally:
        # This synthetic wrapper's native stream actually closed before raising.
        for stream in opened:
            stream.raw.close()
            if stream in bound._UNCLOSED_LEDGER: bound._UNCLOSED_LEDGER.remove(stream)
        if released: _fixture_dispose_attempts(output)


class ObservedPipe(io.BytesIO):
    def __init__(self,raw): super().__init__(raw); self.close_calls=0
    def close(self): self.close_calls+=1; super().close()


def capture_fixture(root,stdout=None):
    output=budget(root)
    process=SimpleNamespace(stdout=stdout if stdout is not None else ObservedPipe(b'prefix'),
                            stderr=ObservedPipe(b'error'),pid=19,args=['synthetic'])
    entry=SimpleNamespace(clock=time.monotonic,deadline=output.deadline,remaining=lambda:output.deadline-time.monotonic())
    capture=pipes.PipeCapture(process,output,{name:root/('focused.'+name) for name in ('stdout','stderr')},entry)
    capture.sinks={name:output.open(path) for name,path in capture.paths.items()}
    return capture,process


def dispose_known_synthetic_capture(capture):
    # Only fixture-owned fake-not-started channels or actual joined targets;
    # production must never use this as evidence resolving start uncertainty.
    for sink in capture.sinks.values():
        if not sink.closed: sink.close()
    for owner in capture.owners.values():
        if owner['pipe'] is not None and not owner['pipe'].closed: owner['pipe'].close()
    if capture in pipes._UNCLOSED: pipes._UNCLOSED.remove(capture)


def test_first_start_exception_without_entry_does_not_join_or_close_uncertain_owner(tmp_path,monkeypatch):
    capture,process=capture_fixture(tmp_path); primary=RuntimeError('first start')
    class UnknownStart:
        ident=None
        def __init__(self,**kwargs): self.joins=0
        def start(self): raise primary
        def join(self,**kwargs): self.joins+=1; raise AssertionError('must not join unstarted association')
        def is_alive(self): return False  # Not evidence that native start did not occur.
    try:
        with monkeypatch.context() as fault:
            fault.setattr(pipes.threading,'Thread',UnknownStart)
            with pytest.raises(RuntimeError) as caught: capture.start()
            assert caught.value is primary and capture in pipes._UNCLOSED
            with pytest.raises(bound.OutputRefusal,match='UNCONFIRMED'): capture.finish(deadline=time.monotonic())
            assert capture.owners['stdout']['thread'].joins==0
            assert not capture.sinks['stdout'].closed and not process.stdout.closed
            assert capture.sinks['stderr'].closed and process.stderr.closed
            assert capture.rows['stdout']['reader_start']=='ATTEMPTED_UNCONFIRMED'
            assert capture.rows['stderr']['reader_start']=='NOT_ATTEMPTED'
            assert not capture.complete() and capture in pipes._UNCLOSED
    finally: dispose_known_synthetic_capture(capture)


@pytest.mark.parametrize('failed_index', (0, 1))
def test_start_exception_after_real_or_prior_live_reader_keeps_prefix_and_holder(tmp_path,monkeypatch,failed_index):
    import threading
    actual_thread=threading.Thread; entered=threading.Event(); release=threading.Event()
    primary=RuntimeError('actual start failure'); probes=[]
    class BlockedPipe(ObservedPipe):
        def __init__(self): super().__init__(b'prefix'); self.reads=0
        def read(self,n):
            self.reads+=1
            if self.reads==1: return super().read(n)
            entered.set()
            if not release.wait(timeout=3): raise OSError('fixture release did not arrive')
            return b''
    capture,process=capture_fixture(tmp_path,BlockedPipe())
    class StartProbe:
        def __init__(self,**kwargs):
            self.index=len(probes); self.raw=actual_thread(**kwargs); self.join_calls=0
            self.real_start_returned=False; probes.append(self)
        def start(self):
            if self.index==failed_index:
                if failed_index==0:
                    self.raw.start(); self.real_start_returned=True
                    assert entered.wait(timeout=2)  # Real OS start then throw.
                else: assert entered.wait(timeout=2)  # Previous reader truly live.
                raise primary
            self.raw.start(); self.real_start_returned=True
        def join(self,**kwargs): self.join_calls+=1; self.raw.join(**kwargs)
        def is_alive(self): return self.raw.is_alive()
    try:
        with monkeypatch.context() as fault:
            fault.setattr(pipes.threading,'Thread',StartProbe)
            with pytest.raises(RuntimeError) as caught: capture.start()
            assert caught.value is primary and capture in pipes._UNCLOSED
            with pytest.raises(bound.OutputRefusal,match='UNCONFIRMED'): capture.finish(deadline=time.monotonic())
            assert process.stdout.close_calls==0 and not capture.sinks['stdout'].closed
            assert (tmp_path/'focused.stdout').read_bytes()==b'prefix'
            assert not capture.rows['stdout']['reader_joined'] and not capture.complete()
            if failed_index==0:
                assert capture.rows['stdout']['reader_entered']
                assert capture.rows['stdout']['reader_start']=='ATTEMPTED_UNCONFIRMED'
                assert capture.sinks['stderr'].closed and process.stderr.closed
            else:
                assert probes[1].join_calls==0
                assert not capture.sinks['stderr'].closed and not process.stderr.closed
            release.set(); probes[0].raw.join(timeout=2); assert not probes[0].raw.is_alive()
            if failed_index==0:
                capture.finish(); assert capture not in pipes._UNCLOSED
            else:
                with pytest.raises(bound.OutputRefusal,match='UNCONFIRMED'): capture.finish()
                assert capture in pipes._UNCLOSED  # Second attempted start remains unknown.
    finally:
        release.set()
        if probes and probes[0].real_start_returned:
            probes[0].raw.join(timeout=2)
            if not probes[0].raw.is_alive(): dispose_known_synthetic_capture(capture)
        # If even the fixture's underlying native start/join remains uncertain,
        # keep the owner and never force-close a live reader from this thread.


def test_not_attempted_channels_all_close_after_thread_construction_and_close_fault(tmp_path,monkeypatch):
    capture,process=capture_fixture(tmp_path); primary=OSError('thread construction')
    original=capture.sinks['stdout'].close; closes=[]
    def refused_close(): closes.append('stdout'); original(); raise OSError('sink close secondary')
    def refused_thread(**kwargs): raise primary
    try:
        with monkeypatch.context() as fault:
            fault.setattr(capture.sinks['stdout'],'close',refused_close)
            fault.setattr(pipes.threading,'Thread',refused_thread)
            with pytest.raises(OSError) as caught: capture.start()
            assert caught.value is primary
            with pytest.raises(OSError) as later: capture.finish()
            assert 'sink close secondary' in str(later.value)
            assert closes==['stdout'] and process.stdout.closed and process.stderr.closed
            assert capture.sinks['stderr'].closed and capture in pipes._UNCLOSED
            assert not capture.complete()  # Failed closure observation is not repaired by closed attribute.
    finally: dispose_known_synthetic_capture(capture)


@pytest.mark.parametrize('failed_index', (0, 1))
def test_actual_runner_retains_start_primary_through_secondary_closure(tmp_path,monkeypatch,failed_index):
    from workloads.m12_adjudication_verify.bounded_runner import Runner
    capture,process=capture_fixture(tmp_path)
    # Use this fresh output ledger but let Runner itself preopen its actual sinks.
    for sink in capture.sinks.values(): sink.close()
    out=tmp_path/'run'; out.mkdir(); output=budget(out)
    entry=SimpleNamespace(clock=time.monotonic,deadline=output.deadline,remaining=lambda:output.deadline-time.monotonic(),
                          timeout=lambda cap,**kwargs:cap)
    runner=Runner(tmp_path,out,{},entry,output); primary=RuntimeError('runner start primary'); probes=[]
    class StartProbe:
        def __init__(self,**kwargs): self.index=len(probes); self.kwargs=kwargs; probes.append(self)
        def start(self):
            if self.index==failed_index: raise primary
            self.kwargs['target'](*self.kwargs['args'])  # Exact helper, synchronous synthetic target.
        def join(self,**kwargs):
            if self.index==failed_index: raise AssertionError('must not join unknown startup')
        def is_alive(self): return False
    def secondary_close(child): raise OSError('secondary child cleanup')
    held=None
    try:
        with monkeypatch.context() as fault:
            fault.setattr(pipes.threading,'Thread',StartProbe)
            fault.setattr(runner,'_spawn',lambda command,**kwargs:process)
            fault.setattr(runner,'_close_child',secondary_close)
            with pytest.raises(RuntimeError) as caught: runner.run('focused',['synthetic'],10)
            assert caught.value is primary and not runner.steps[-1]['output_complete']
            assert any('OSError' in note for note in primary.__notes__)
            held=next(holder for holder in pipes._UNCLOSED if holder.process is process)
            assert held.rows[('stdout','stderr')[failed_index]]['reader_start']=='ATTEMPTED_UNCONFIRMED'
            assert (out/'output-refusal.json').exists()
    finally:
        if held is not None: dispose_known_synthetic_capture(held)


def test_actual_runner_without_capture_closes_all_unassigned_resources_independently(tmp_path,monkeypatch):
    from workloads.m12_adjudication_verify import bounded_runner as runners
    output=budget(tmp_path); entry=SimpleNamespace(clock=time.monotonic,deadline=output.deadline,
        remaining=lambda:output.deadline-time.monotonic(),timeout=lambda cap,**kwargs:cap)
    runner=runners.Runner(tmp_path,tmp_path,{},entry,output)
    process=SimpleNamespace(stdout=ObservedPipe(b'prefix'),stderr=ObservedPipe(b'error'),pid=19)
    primary=OSError('capture construction'); opened=[]; original_open=bound.OutputBudget.open
    def watched_open(owner,path):
        sink=original_open(owner,path); opened.append(sink)
        if path.name=='focused.stdout':
            close=sink.close
            def faulted_close(): close(); raise OSError('unassigned sink secondary')
            sink.close=faulted_close
        return sink
    def no_capture(child,name,**kwargs): raise primary
    with monkeypatch.context() as fault:
        fault.setattr(bound.OutputBudget,'open',watched_open)
        fault.setattr(runner,'_spawn',lambda command,**kwargs:process)
        fault.setattr(runner,'_capture',no_capture)
        fault.setattr(runner,'_close_child',lambda child:{'parent_reaped':False})
        with pytest.raises(OSError) as caught: runner.run('focused',['synthetic'],10)
        assert caught.value is primary
        assert all(sink.closed for sink in opened) and process.stdout.closed and process.stderr.closed
        assert not runner.steps[-1]['output_complete']
        assert any('OSError' in note for note in primary.__notes__)
    # No native child existed, and these synthetic streams actually closed.
    for holder in list(runners._UNCLOSED_UNASSIGNED):
        if holder['process'] is process: runners._UNCLOSED_UNASSIGNED.remove(holder)


def test_closed_diagnostic_never_serializes_unknown_message_or_mutated_fields():
    import json
    error=bound.OutputRefusal('SECRET arbitrary path/command')
    safe=dict(reason_code='OUTPUT_REFUSAL_UNCLASSIFIED',operation='unclassified',stage='unclassified')
    assert bound.refusal_diagnostic(error)==safe
    error._output_diagnostic=('SECRET',[], 'command')  # Invalid/unhashable caller look-alike.
    assert bound.refusal_diagnostic(error)==safe
    assert 'SECRET' not in json.dumps(bound.refusal_diagnostic(error))
    assert bound.refusal_diagnostic(OSError('SECRET')) is None


def test_actual_mutex_refusal_and_original_entry_deadline_have_distinct_reasons(tmp_path,monkeypatch):
    now=[0.0]; output=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    raw_before=output.path.read_bytes()
    def refused_acquire(actual,*,timeout):
        assert actual is output.mutex; now[0]+=.25; return False
    def forbidden_release(actual): raise AssertionError('unacquired mutex must not release')
    with monkeypatch.context() as fault:
        fault.setattr(bound,'_acquire_output_mutex',refused_acquire)
        fault.setattr(bound,'_release_output_mutex',forbidden_release)
        with pytest.raises(bound.OutputRefusal) as waited: output.charge(1)
        assert bound.refusal_diagnostic(waited.value)==dict(reason_code='MUTEX_WAIT_EXHAUSTED',operation='mutex',stage='wait')
        assert output.path.read_bytes()==raw_before and output.deadline==10
        now[0]=10
        with pytest.raises(bound.OutputRefusal) as expired: output.charge(1)
        assert bound.refusal_diagnostic(expired.value)==dict(reason_code='OUTPUT_DEADLINE',operation='ledger',stage='charge')
        assert output.path.read_bytes()==raw_before


def test_actual_file_lock_loop_preserves_refusal_reason_and_uncharged_ledger(tmp_path,monkeypatch):
    now=[0.0]; output=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    raw_before=output.path.read_bytes(); calls=[]
    def lock_refused(*args): calls.append(args); raise BlockingIOError(bound.errno.EAGAIN,'lock contention fixture')
    with monkeypatch.context() as fault:
        if bound.os.name=='nt':
            import msvcrt
            fault.setattr(msvcrt,'locking',lock_refused)
        else:
            import fcntl
            fault.setattr(fcntl,'flock',lock_refused)
        fault.setattr(bound.time,'sleep',lambda delay:now.__setitem__(0,now[0]+.05))
        with pytest.raises(bound.OutputRefusal) as caught: output.charge(1)
    assert calls and bound.refusal_diagnostic(caught.value)==dict(reason_code='OUTPUT_DEADLINE',operation='file_lock',stage='wait')
    assert not output.mutex.locked() and output.path.read_bytes()==raw_before
    assert output.deadline==10  # Same absolute deadline; no increased cap/reset.


class SynchronousSyntheticThread:
    """Calls the production reader; no native thread/start qualification claim."""
    def __init__(self,*,target,args,daemon): self.target,self.args=target,args
    def start(self): self.target(*self.args)
    def join(self,**kwargs): pass
    def is_alive(self): return False


def runner_fixture(root):
    from workloads.m12_adjudication_verify.bounded_runner import Runner
    output=budget(root)
    entry=SimpleNamespace(clock=time.monotonic,deadline=output.deadline,started=time.monotonic(),
        remaining=lambda:output.deadline-time.monotonic(),timeout=lambda cap,**kwargs:cap)
    runner=Runner(root,root,{},entry,output)
    process=SimpleNamespace(stdout=ObservedPipe(b'prefix'),stderr=ObservedPipe(b''),pid=19,
                            args=['synthetic'],returncode=0,poll=lambda:0)
    return runner,process,entry


@pytest.fixture
def retained_synthetic_captures():
    # These tests own only BytesIO pipes and synchronous synthetic thread targets.
    # This fixture cleanup must never resolve a production unknown native owner.
    held=[]
    try: yield held
    finally:
        for capture in held: dispose_known_synthetic_capture(capture)


def test_actual_runner_first_refusal_survives_secondary_close_and_wrapper_cannot_complete(tmp_path,monkeypatch,retained_synthetic_captures):
    import json
    from workloads.m12_adjudication_verify import partitioned
    runner,process,entry=runner_fixture(tmp_path)
    opened=[]; captures=retained_synthetic_captures; actual_open=bound.OutputBudget.open; actual_capture=runner._capture
    def watched_capture(child,name,**kwargs):
        capture=actual_capture(child,name,**kwargs); captures.append(capture); return capture
    def watched_open(owner,path):
        writer=actual_open(owner,path)
        if path.name=='focused.stdout':
            opened.append(writer); original_close=writer.close
            def secondary_close(): original_close(); raise OSError('SECRET secondary close')
            writer.close=secondary_close
        return writer
    def refused_child_close(child): raise OSError('SECRET secondary child cleanup')
    with monkeypatch.context() as fault:
        fault.setitem(bound.CAPS,'focused.stdout',3)
        fault.setattr(bound.OutputBudget,'open',watched_open)
        fault.setattr(pipes.threading,'Thread',SynchronousSyntheticThread)
        fault.setattr(runner,'_spawn',lambda command,**kwargs:process)
        fault.setattr(runner,'_capture',watched_capture)
        fault.setattr(runner,'_close_child',refused_child_close)
        with pytest.raises(bound.OutputRefusal) as caught: runner.run('focused',['synthetic'],10)
        row=runner.steps[-1]; saved=json.loads((tmp_path/'output-refusal.json').read_bytes())
        assert caught.value is captures[0].errors[0]
        assert row['exit_code']==2 and row['child_return_observed'] is False and row['child_return_code'] is None
        assert row['execution_stage']=='focused' and row['refusal_diagnostic']==saved['refusal_diagnostic']
        assert saved['refusal_diagnostic']==dict(reason_code='FILE_CAP',operation='pipe_reader',stage='read')
        assert row['streams']['stdout']['refusal_diagnostic']==saved['refusal_diagnostic']
        assert row['streams']['stdout']['eof'] is False and row['streams']['stdout']['sha256'] is None
        assert (tmp_path/'focused.stdout').read_bytes()==b'pre' and not row['output_complete']
        assert opened[0].closed and any('OSError' in note for note in caught.value.__notes__)
        assert b'SECRET' not in (tmp_path/'output-refusal.json').read_bytes()
        fault.setattr(partitioned,'_OUTPUT',runner.output)
        result=dict(phase_checks_complete=False,shard='0',actual_sha='a'*40,host=partitioned.HOST,
                    problems=['partition evidence incomplete'],limitations=[])
        assert partitioned.finalize(tmp_path,result,entry)==1
        marker=json.loads((tmp_path/'terminal.json').read_bytes())
        assert marker['ready_for_native_terminal'] is False and marker['partition_complete'] is False
        assert result['partition_complete'] is False


def test_actual_runner_success_records_return_separately_from_capture_refusal(tmp_path,monkeypatch):
    runner,process,entry=runner_fixture(tmp_path)
    with monkeypatch.context() as fault:
        fault.setattr(pipes.threading,'Thread',SynchronousSyntheticThread)
        fault.setattr(runner,'_spawn',lambda command,**kwargs:process)
        assert runner.run('focused',['synthetic'],10)==0
    row=runner.steps[-1]
    assert row['child_return_observed'] is True and row['child_return_code']==0 and row['output_complete']
    assert row['refusal_diagnostic'] is None and all(channel['eof'] for channel in row['streams'].values())
    assert (tmp_path/'focused.stdout').read_bytes()==b'prefix'


@pytest.mark.parametrize('unobserved_return',(True,None,'0'))
def test_full_pipe_capture_cannot_turn_unknown_child_return_into_observed_success(tmp_path,monkeypatch,unobserved_return):
    runner,process,entry=runner_fixture(tmp_path); process.returncode=unobserved_return
    with monkeypatch.context() as fault:
        fault.setattr(pipes.threading,'Thread',SynchronousSyntheticThread)
        fault.setattr(runner,'_spawn',lambda command,**kwargs:process)
        fault.setattr(runner,'_close_child',lambda child:{'parent_reaped':False})
        with pytest.raises(bound.OutputRefusal) as caught: runner.run('focused',['synthetic'],10)
    row=runner.steps[-1]
    assert bound.refusal_diagnostic(caught.value)==dict(reason_code='UNKNOWN_CHILD_RETURN',operation='child_runner',stage='complete')
    assert row['child_return_observed'] is False and row['child_return_code'] is None
    assert not row['output_complete'] and all(channel['eof'] for channel in row['streams'].values())


def test_late_ledger_io_keeps_actual_attempt_charge_and_distinct_diagnostic(tmp_path,monkeypatch):
    now=[0.0]; output=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    actual_fsync=bound.os.fsync
    def slow_fsync(fd): actual_fsync(fd); now[0]=10
    with monkeypatch.context() as fault:
        fault.setattr(bound.os,'fsync',slow_fsync)
        with pytest.raises(bound.OutputRefusal) as caught: output.charge(7)
    assert bound.refusal_diagnostic(caught.value)==dict(reason_code='LATE_LEDGER_IO',operation='ledger',stage='write')
    _,attempted,files,sequence,_=bound.STATE.unpack(output.path.read_bytes())
    assert attempted==2*bound.STATE.size+7 and files==1 and sequence==1
    assert not output.mutex.locked() and output.deadline==10


def test_stage_clone_shares_original_ledger_mutex_clock_and_cannot_extend(tmp_path):
    now=[0.0]; original=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    before=original.path.read_bytes(); owner=original.for_stage('focused',2)
    assert owner.path==original.path and owner.clock is original.clock and owner.mutex is original.mutex
    assert owner._mutex_custody is original._mutex_custody
    with pytest.raises(AttributeError): owner.mutex=original.mutex
    assert original.path.read_bytes()==before and owner.entry_deadline==10 and owner.deadline==2
    owner.charge(3)
    _,attempted,files,seq,_=bound.STATE.unpack(original.path.read_bytes())
    assert attempted==2*bound.STATE.size+3 and files==1 and seq==1
    with pytest.raises(bound.OutputRefusal): owner.for_stage('partition',3)
    now[0]=2
    with pytest.raises(bound.OutputRefusal): owner.charge(1)
    assert original.deadline==10 and original.stage_name=='entry'


@pytest.mark.parametrize('stage,deadline',(('unknown',1),('entry',1),('focused',True),('focused','1'),
    ('focused',float('nan')),('focused',float('inf')),('focused',11),('focused',0)))
def test_stage_acquisition_rejects_wrong_type_role_nonfinite_and_extended_deadline(tmp_path,stage,deadline):
    original=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:0)
    before=original.path.read_bytes()
    with pytest.raises(bound.OutputRefusal): original.for_stage(stage,deadline)
    assert original.path.read_bytes()==before


@pytest.mark.parametrize('fields',({'SL_OUTPUT_STAGE':None},{'SL_OUTPUT_STAGE':'collection'},
    {'SL_OUTPUT_STAGE':'entry'},{'SL_OUTPUT_STAGE_DEADLINE':'nan'}, {'SL_OUTPUT_STAGE_DEADLINE':'inf'},
    {'SL_OUTPUT_STAGE_DEADLINE':'-1'},{'SL_OUTPUT_STAGE_DEADLINE':'1'}, {'SL_OUTPUT_STAGE_DEADLINE':None}))
def test_child_requires_actual_expected_role_and_original_finite_live_stage(tmp_path,monkeypatch,fields):
    original=budget(tmp_path); before=original.path.read_bytes()
    values=dict(SL_OUTPUT_ROOT=str(tmp_path),SL_OUTPUT_DEADLINE=repr(original.entry_deadline),
        SL_OUTPUT_STAGE='focused',SL_OUTPUT_STAGE_DEADLINE=repr(original.entry_deadline-1))
    with monkeypatch.context() as fault:
        for key,value in values.items(): fault.setenv(key,value)
        for key,value in fields.items():
            if value is None: fault.delenv(key,raising=False)
            else: fault.setenv(key,value)
        with pytest.raises(bound.OutputRefusal): bound.OutputBudget.child(expected_stage='focused')
    assert original.path.read_bytes()==before


def _locked_charge_thread(owner):
    import threading
    entered=threading.Event(); errors=[]
    def actual():
        entered.set()
        try: owner.charge(9)
        except BaseException as error: errors.append(error)
    worker=threading.Thread(target=actual)
    worker.start(); assert entered.wait(timeout=2)
    return worker,errors


@pytest.mark.parametrize('native_lock',(False,True))
def test_actual_mutex_or_native_file_lock_progress_after_200ms_with_same_stage(tmp_path,native_lock):
    original=budget(tmp_path); owner=original.for_stage('focused',time.monotonic()+10)
    raw=original.path.open('r+b',buffering=0) if native_lock else None
    if native_lock:
        raw.seek(0)
        if bound.os.name=='nt':
            import msvcrt
            msvcrt.locking(raw.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(raw.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    else: original.mutex.acquire()
    worker=None; released=False
    try:
        began=time.monotonic(); worker,errors=_locked_charge_thread(owner)
        time.sleep(.35)
        if native_lock: bound._unlock_output_stream(raw)
        else: original.mutex.release()
        released=True; worker.join(timeout=12)
        assert not worker.is_alive() and not errors and time.monotonic()-began>.2
        _,attempted,files,seq,_=bound.STATE.unpack(original.path.read_bytes())
        assert attempted==2*bound.STATE.size+9 and files==1 and seq==1
        assert owner.deadline<=original.entry_deadline and owner.stage_name=='focused'
    finally:
        if not released:
            if native_lock: bound._unlock_output_stream(raw)
            else: original.mutex.release()
        if raw is not None: raw.close()
        if worker is not None: worker.join(timeout=12)


def test_actual_mutex_stage_expiry_keeps_uncharged_ledger_without_new_deadline(tmp_path):
    original=budget(tmp_path); deadline=time.monotonic()+.25
    owner=original.for_stage('focused',deadline); before=original.path.read_bytes(); original.mutex.acquire()
    worker=None
    try:
        worker,errors=_locked_charge_thread(owner); worker.join(timeout=2)
        assert not worker.is_alive() and len(errors)==1 and isinstance(errors[0],bound.OutputRefusal)
        assert bound.refusal_diagnostic(errors[0])['reason_code']=='MUTEX_WAIT_EXHAUSTED'
        assert original.path.read_bytes()==before and owner.deadline==deadline
    finally:
        original.mutex.release()
        if worker is not None: worker.join(timeout=2)


def test_noncontention_native_lock_error_is_preserved_once_not_retried(tmp_path,monkeypatch):
    original=budget(tmp_path); error=OSError(bound.errno.EINVAL,'SECRET invalid lock'); calls=[]
    def unknown_lock(*args): calls.append(args); raise error
    with monkeypatch.context() as fault:
        if bound.os.name=='nt':
            import msvcrt
            fault.setattr(msvcrt,'locking',unknown_lock)
        else:
            import fcntl
            fault.setattr(fcntl,'flock',unknown_lock)
        with pytest.raises(OSError) as caught: original.charge(1)
    assert caught.value is error and len(calls)==1 and not original.mutex.locked()


def test_late_mutex_return_releases_actual_known_owner_and_rejects_charge(tmp_path,monkeypatch):
    now=[0.0]; original=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    owner=original.for_stage('focused',1); before=original.path.read_bytes(); real=original.mutex
    def late_acquire(actual,*,timeout):
        assert actual is real; result=actual.acquire(timeout=timeout); now[0]=1; return result
    with monkeypatch.context() as fault:
        fault.setattr(bound,'_acquire_output_mutex',late_acquire)
        with pytest.raises(bound.OutputRefusal) as caught: owner.charge(1)
        assert bound.refusal_diagnostic(caught.value)['operation']=='mutex'
        assert not real.locked() and original.path.read_bytes()==before
        assert not any(attempt.custody is original._mutex_custody for attempt in bound._UNCLOSED_MUTEX)


def test_runner_hands_identical_stage_to_parent_channels_and_actual_child_environment(tmp_path,monkeypatch):
    runner,process,entry=runner_fixture(tmp_path); environments=[]
    def observed_spawn(command,*,environment): environments.append(environment); return process
    with monkeypatch.context() as fault:
        fault.setattr(pipes.threading,'Thread',SynchronousSyntheticThread)
        fault.setattr(runner,'_spawn',observed_spawn)
        assert runner.run('focused',['synthetic'],10)==0
    row=runner.steps[-1]; environment=environments[0]
    assert row['execution_stage']=='focused' and environment['SL_OUTPUT_STAGE']=='focused'
    assert float(environment['SL_OUTPUT_STAGE_DEADLINE'])==row['stage_absolute_deadline']
    assert float(environment['SL_OUTPUT_DEADLINE'])==entry.deadline
    assert all(channel['execution_stage']=='focused' and channel['stage_absolute_deadline']==row['stage_absolute_deadline']
               for channel in row['streams'].values())
    assert runner.output.stage_name=='entry' and runner.output.deadline==entry.deadline


@pytest.mark.parametrize('bad_cap',(True,None,'10',float('nan'),float('inf'),0))
def test_runner_invalid_stage_cap_starts_no_child_and_never_claims_return(tmp_path,monkeypatch,bad_cap):
    runner,process,entry=runner_fixture(tmp_path)
    def forbidden(*args,**kwargs): raise AssertionError('invalid stage must not spawn')
    monkeypatch.setattr(runner,'_spawn',forbidden)
    with pytest.raises(bound.OutputRefusal): runner.run('focused',['synthetic'],bad_cap)
    row=runner.steps[-1]
    assert not row['started'] and row['execution_stage'] is None and not row['child_return_observed']


def test_expired_focus_still_uses_independent_actual_cleanup_deadline(tmp_path,monkeypatch):
    import json
    from workloads.m12_adjudication_verify import bounded_runner as runners,partitioned
    now=[0.0]; entry=partitioned.Budget(clock=lambda:now[0])
    output=bound.OutputBudget(tmp_path,entry.deadline,create=True,clock=entry.clock)
    runner=runners.Runner(tmp_path,tmp_path,{'SYSTEMROOT':'C:\\Windows'},entry,output); environments=[]
    process=SimpleNamespace(pid=19,poll=lambda:0,wait=lambda **kwargs:9,
        stdout=ObservedPipe(b''),stderr=ObservedPipe(b''))
    killer=SimpleNamespace(pid=20,poll=lambda:0,returncode=0,args=['synthetic-cleanup'],
        stdout=ObservedPipe(b''),stderr=ObservedPipe(b''))
    def spawn(command,*,environment):
        environments.append(environment)
        if len(environments)==1: now[0]=2; return process
        return killer
    with monkeypatch.context() as fault:
        fault.setattr(runners.sys,'platform','win32')
        fault.setattr(pipes.threading,'Thread',SynchronousSyntheticThread)
        fault.setattr(runner,'_spawn',spawn)
        assert runner.run('focused',['synthetic'],1)==124
    row=runner.steps[-1]
    assert row['timed_out'] and not row['child_return_observed'] and not row['output_complete']
    assert environments[0]['SL_OUTPUT_STAGE']=='focused' and float(environments[0]['SL_OUTPUT_STAGE_DEADLINE'])==1
    assert environments[1]['SL_OUTPUT_STAGE']=='child_cleanup' and float(environments[1]['SL_OUTPUT_STAGE_DEADLINE'])==17
    assert row['cleanup']['cleanup_return_observed'] and row['cleanup']['cleanup_return_code']==9
    assert all(channel['execution_stage']=='child_cleanup' for channel in row['cleanup']['taskkill_streams'].values())
    assert json.loads((tmp_path/'output-refusal.json').read_bytes())['primary_type']=='TimeoutExpired'
    # Only these fixture-owned BytesIO objects physically closed; no native proof.
    for holder in list(runners._UNCLOSED_UNASSIGNED):
        if holder['process'] is process and process.stdout.closed and process.stderr.closed:
            runners._UNCLOSED_UNASSIGNED.remove(holder)


@pytest.mark.parametrize('fault_at',('acquire','release'))
def test_real_mutex_unknown_attempt_is_sticky_across_repeat_and_stage_views(tmp_path,monkeypatch,fault_at):
    original=budget(tmp_path); owner=original.for_stage('focused',time.monotonic()+10)
    other=original.for_stage('partition',owner.deadline)
    actual=original.mutex; primary=OSError('SECRET uncertain mutex'); calls=[]; real_take=[]
    def observed_acquire(mutex,*,timeout):
        assert mutex is actual; calls.append('acquire')
        result=mutex.acquire(timeout=timeout)
        if result is True: real_take.append(mutex)
        if fault_at=='acquire':
            assert result is True; raise primary  # Genuine take precedes fault.
        return result
    def observed_release(mutex):
        assert mutex is actual; calls.append('release'); mutex.release()
        if fault_at=='release': raise primary  # Genuine release precedes fault.
    with monkeypatch.context() as fault:
        fault.setattr(bound,'_acquire_output_mutex',observed_acquire)
        fault.setattr(bound,'_release_output_mutex',observed_release)
        try:
            with pytest.raises(OSError) as caught: owner.charge(1)
            assert caught.value is primary
            held=[attempt for attempt in bound._UNCLOSED_MUTEX if attempt.custody is original._mutex_custody]
            assert len(held)==1 and held[0].owner is owner and held[0].primary is primary
            assert held[0].state==('ACQUIRE_UNCONFIRMED' if fault_at=='acquire' else 'RELEASE_UNCONFIRMED')
            before=original.path.read_bytes(); consumed=list(calls)
            for next_owner in (owner,other,original):
                with pytest.raises(bound.OutputRefusal) as refused: next_owner.charge(2)
                assert bound.refusal_diagnostic(refused.value)['reason_code']=='MUTEX_CUSTODY_UNCONFIRMED'
                assert calls==consumed and original.path.read_bytes()==before
                assert [attempt for attempt in bound._UNCLOSED_MUTEX if attempt.custody is original._mutex_custody]==held
        finally:
            if fault_at=='acquire' and real_take: actual.release()  # This fixture actually took it.
            _fixture_dispose_attempts(original)  # Private fixture disposal, no reset/reuse.


@pytest.mark.parametrize('same_view',(False,True))
def test_real_concurrent_success_cannot_erase_other_pending_then_unknown_take(tmp_path,monkeypatch,same_view):
    import threading
    original=budget(tmp_path); first=original.for_stage('focused',time.monotonic()+10)
    second=first if same_view else original.for_stage('partition',first.deadline)
    actual=original.mutex; errors={}; calls=[]; took=[]; primary=OSError('second acquire after take')
    first_in_io=threading.Event(); second_entered=threading.Event(); continue_second=threading.Event()
    real_fsync=bound.os.fsync
    def observe_fsync(fd):
        real_fsync(fd)
        if threading.current_thread().name=='first':
            first_in_io.set(); assert second_entered.wait(timeout=3)
    def observe_acquire(mutex,*,timeout):
        name=threading.current_thread().name; calls.append(name); assert mutex is actual
        if name=='second':
            second_entered.set(); assert continue_second.wait(timeout=3)
        result=mutex.acquire(timeout=timeout)
        if name=='second':
            assert result is True; took.append(mutex); raise primary
        return result
    def run(name,owner):
        try: owner.charge(3)
        except BaseException as error: errors[name]=error
    threads=[threading.Thread(name=name,target=run,args=(name,owner)) for name,owner in (('first',first),('second',second))]
    with monkeypatch.context() as fault:
        fault.setattr(bound.os,'fsync',observe_fsync)
        fault.setattr(bound,'_acquire_output_mutex',observe_acquire)
        try:
            threads[0].start(); assert first_in_io.wait(timeout=3)
            threads[1].start(); assert second_entered.wait(timeout=3)
            threads[0].join(timeout=3); assert not threads[0].is_alive() and 'first' not in errors
            pending=[attempt for attempt in bound._UNCLOSED_MUTEX if attempt.custody is original._mutex_custody]
            assert len(pending)==1 and pending[0].owner is second and pending[0].state=='ACQUIRE_PENDING'
            before=original.path.read_bytes()
            continue_second.set(); threads[1].join(timeout=3)
            assert not threads[1].is_alive() and errors['second'] is primary
            assert pending[0] in bound._UNCLOSED_MUTEX and pending[0].primary is primary
            assert original.path.read_bytes()==before  # Unknown take never writes another charge.
            with pytest.raises(bound.OutputRefusal): first.charge(1)
            assert calls==['first','second'] and pending[0] in bound._UNCLOSED_MUTEX
        finally:
            continue_second.set(); second_entered.set()
            for thread in threads:
                if thread.ident is not None: thread.join(timeout=3)
            if all(not thread.is_alive() for thread in threads):
                if took: actual.release()  # Exact real take is known only to this fixture.
                _fixture_dispose_attempts(original)


@pytest.mark.parametrize('wait_returns',(False,True))
def test_inflight_known_outcome_retires_only_itself_after_other_release_uncertainty(tmp_path,monkeypatch,wait_returns):
    import threading
    original=budget(tmp_path); first=original.for_stage('focused',time.monotonic()+10)
    second=original.for_stage('partition',first.deadline)
    actual=original.mutex; errors={}; calls=[]; fixture_take=[]; primary=OSError('first release after release')
    first_releasing=threading.Event(); second_entered=threading.Event(); continue_second=threading.Event()
    def acquire(mutex,*,timeout):
        name=threading.current_thread().name; calls.append(('acquire',name)); assert mutex is actual
        if name=='second':
            second_entered.set(); assert continue_second.wait(timeout=3)
            # Real known false timeout over the same original remaining bound,
            # or real known success; neither resolves the other attempt.
            if not wait_returns: timeout=min(timeout,.05)
        return mutex.acquire(timeout=timeout)
    def release(mutex):
        name=threading.current_thread().name; calls.append(('release',name)); assert mutex is actual
        mutex.release()
        if name=='first':
            first_releasing.set(); assert second_entered.wait(timeout=3); raise primary
    def run(name,owner):
        try: owner.charge(4)
        except BaseException as error: errors[name]=error
    threads=[threading.Thread(name=name,target=run,args=(name,owner)) for name,owner in (('first',first),('second',second))]
    with monkeypatch.context() as fault:
        fault.setattr(bound,'_acquire_output_mutex',acquire)
        fault.setattr(bound,'_release_output_mutex',release)
        try:
            threads[0].start(); assert first_releasing.wait(timeout=3)
            threads[1].start(); assert second_entered.wait(timeout=3)
            threads[0].join(timeout=3); assert not threads[0].is_alive() and errors['first'] is primary
            held=[attempt for attempt in bound._UNCLOSED_MUTEX if attempt.custody is original._mutex_custody]
            uncertain=next(attempt for attempt in held if attempt.owner is first)
            assert len(held)==2 and uncertain.primary is primary and uncertain.state=='RELEASE_UNCONFIRMED'
            if not wait_returns:
                assert actual.acquire(timeout=1); fixture_take.append(actual)
            before=original.path.read_bytes(); continue_second.set(); threads[1].join(timeout=3)
            assert not threads[1].is_alive() and isinstance(errors['second'],bound.OutputRefusal)
            assert original.path.read_bytes()==before
            assert [attempt for attempt in bound._UNCLOSED_MUTEX if attempt.custody is original._mutex_custody]==[uncertain]
            consumed=list(calls)
            with pytest.raises(bound.OutputRefusal): original.charge(1)
            assert calls==consumed and uncertain in bound._UNCLOSED_MUTEX
            assert ('release','second') in calls if wait_returns else ('release','second') not in calls
        finally:
            continue_second.set(); second_entered.set()
            for thread in threads:
                if thread.ident is not None: thread.join(timeout=3)
            if all(not thread.is_alive() for thread in threads):
                if fixture_take: actual.release()  # Fixture-owned external take.
                _fixture_dispose_attempts(original)


def test_late_real_flush_cannot_succeed_or_overwrite_primary_during_close(tmp_path):
    now=[0.0]; original=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    owner=original.for_stage('focused',1); writer=owner.open(tmp_path/'focused.stdout'); writer.write(b'prefix')
    real=writer.stream
    class LateFlush:
        def flush(self): real.flush(); now[0]=1
        def fileno(self): return real.fileno()
        def close(self): real.close()
    writer.stream=LateFlush()
    with pytest.raises(bound.OutputRefusal) as caught:
        with writer: writer.flush()
    assert bound.refusal_diagnostic(caught.value)['reason_code']=='LATE_FLUSH_IO'
    assert writer.closed and (tmp_path/'focused.stdout').read_bytes()==b'prefix'
    assert caught.value.__notes__  # The late close is secondary, not a replacement.
