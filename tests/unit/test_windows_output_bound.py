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


def test_per_file_refuses_before_excess_and_preserves_original_calls(tmp_path,monkeypatch):
    with monkeypatch.context() as fault:
        fault.setitem(bound.CAPS,'requirements.txt',3)
        output=budget(tmp_path); stream=output.open(tmp_path/'requirements.txt')
        stream.write(b'abc'); before=output.path.read_bytes()
        with pytest.raises(bound.OutputRefusal): stream.write(b'd')
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
    assert any('OSError' in note for note in caught.value.__notes__)


def test_ledger_partial_or_corrupt_blocks_payload_and_retains_existing_prefix(tmp_path):
    output=budget(tmp_path); writer=output.open(tmp_path/'requirements.txt'); writer.write(b'prefix')
    output.path.write_bytes(b'partial')  # Synthetic fault; never a production repair.
    with pytest.raises(bound.OutputRefusal): writer.write(b'extra')
    writer.close(); assert (tmp_path/'requirements.txt').read_bytes()==b'prefix'


def test_late_real_writer_close_is_refusal_after_actual_prefix(tmp_path):
    now=[0.0]; output=bound.OutputBudget(tmp_path,10,create=True,clock=lambda:now[0])
    writer=output.open(tmp_path/'requirements.txt'); writer.write(b'prefix'); now[0]=10
    with pytest.raises(bound.OutputRefusal,match='late'): writer.close()
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
    mutex=output.mutex
    class Mutex:
        released=False
        def acquire(self,**kwargs): return mutex.acquire(**kwargs)
        def release(self):
            self.released=True; mutex.release()
            if earlier_primary: raise release_fault
    output.mutex=Mutex()
    try:
        with monkeypatch.context() as fault:
            fault.setattr(Path,'open',opened_ledger)
            if fault_at=='unlock':
                def refused_unlock(stream): raise native_fault
                fault.setattr(bound,'_unlock_output_stream',refused_unlock)
            with pytest.raises(OSError) as caught: output.charge(1)
            assert caught.value is (write_primary if earlier_primary else native_fault)
            assert opened[0].close_attempted and opened[0].raw.closed
            assert output.mutex.released and not mutex.locked()
            if earlier_primary:
                assert len(caught.value.__notes__)==3  # Unlock, close, release all attempted.
    finally:
        # This synthetic wrapper's native stream actually closed before raising.
        for stream in opened:
            stream.raw.close()
            if stream in bound._UNCLOSED_LEDGER: bound._UNCLOSED_LEDGER.remove(stream)


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
            fault.setattr(runner,'_spawn',lambda command:process)
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
    primary=OSError('capture construction'); opened=[]; original_open=output.open
    def watched_open(path):
        sink=original_open(path); opened.append(sink)
        if path.name=='focused.stdout':
            close=sink.close
            def faulted_close(): close(); raise OSError('unassigned sink secondary')
            sink.close=faulted_close
        return sink
    def no_capture(child,name): raise primary
    with monkeypatch.context() as fault:
        fault.setattr(output,'open',watched_open)
        fault.setattr(runner,'_spawn',lambda command:process)
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
