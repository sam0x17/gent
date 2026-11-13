#!/usr/bin/env python3
"""Exercise installed Bash/Zsh/Fish startup and completion in isolated files; no models."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import signal
import subprocess
import tempfile
import time


def zsh_tab_completion(shell, env, cwd):
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execvpe(shell, [shell, '-di'], env)
    buffer = b''

    def until(marker):
        nonlocal buffer
        deadline = time.monotonic() + 20
        while marker not in buffer:
            assert time.monotonic() < deadline, repr(buffer[-3000:])
            if select.select([fd], [], [], .1)[0]:
                chunk = os.read(fd, 65536)
                assert chunk, repr(buffer[-3000:])
                buffer += chunk
        buffer = b''

    try:
        until(b'HOOK_PROMPT> ')
        # Complete a nested CLI command, then print the expanded line instead
        # of executing it. This exercises ZLE's actual completion dispatch.
        os.write(fd, b'gent node name s\t')
        time.sleep(.2)
        os.write(fd, b'\x01print -r -- HOOK_COMPLETED:\x05\r')
        until(b'HOOK_COMPLETED:gent node name set')
        os.write(fd, b'exit\r')
    finally:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.close(fd)
        os.waitpid(pid, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/gent'))
    parser.add_argument('--bash', default='/bin/bash')
    parser.add_argument('--zsh', default='/bin/zsh')
    parser.add_argument('--fish', default='fish')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='gent-shell-', dir='/tmp') as root:
        root = Path(root).resolve()
        directory = root / "bin ' $HOME $(touch PWNED) [*] \\slash"
        directory.mkdir()
        binary = directory / 'gent'
        try:
            os.link(args.binary.resolve(), binary)
        except OSError:
            shutil.copy2(args.binary.resolve(), binary)
        state = root / 'unused-state'

        def cli(*command, check=True, env=None):
            result = subprocess.run([str(binary), '--home', str(state), *command],
                                    text=True, capture_output=True, env=env, timeout=15)
            assert not check or result.returncode == 0, result.stderr
            return result

        for name, shell in [('bash', args.bash), ('zsh', args.zsh), ('fish', args.fish)]:
            shell = shutil.which(shell)
            assert shell, f'{name} is unavailable; pass --{name} with its executable path'
            shell = str(Path(shell).resolve())
            startup = root / name
            startup.mkdir(mode=0o700)
            if name == 'fish':
                (startup / 'fish').mkdir(mode=0o700)
            rc = startup / {'bash': '.bashrc', 'zsh': '.zshrc', 'fish': 'fish/config.fish'}[name]
            suffix = ['--shell', name, '--rc-file', str(rc)]
            cli('hooks', 'status', *suffix)
            assert not rc.exists()
            original = 'export GENT_HOOK_PROOF=preserved\n'
            if name == 'fish':
                original = 'set -gx GENT_HOOK_PROOF preserved\n'
            if name == 'zsh':
                original += "PROMPT='HOOK_PROMPT> '\nbindkey -e\n"
            rc.write_text(original)
            rc.chmod(0o600)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for future in [pool.submit(cli, 'hooks', 'install', *suffix) for _ in range(8)]:
                    future.result()
            installed = rc.read_text()
            assert installed.count('# >>> gent shell') == 1
            env = dict(os.environ, PATH='/usr/bin:/bin', HISTFILE=str(startup / 'history'),
                       ZDOTDIR=str(startup), XDG_CONFIG_HOME=str(startup), SHELL=shell, TERM='xterm', GENT_HOME=str(state))
            env.pop('BASH_ENV', None)
            env.pop('ENV', None)
            source = 'source ' + shlex.quote(str(rc))
            check = source + '; test "$GENT_HOOK_PROOF" = preserved || exit 10; command -v gent; '
            if name == 'bash':
                command = [shell, '--noprofile', '--rcfile', str(rc), '-ic']
                check += 'complete -p gent; COMP_WORDS=(gent node name s); COMP_CWORD=3; COMP_LINE="gent node name s"; COMP_POINT=${#COMP_LINE}; _gent gent s name; printf "COMPLETED:%s\\n" "${COMPREPLY[@]}"'
            elif name == 'zsh':
                command = [shell, '-dic']
                check += 'test "${_comps[gent]}" = _gent || exit 11; (( $+functions[_gent] )) || exit 12; print COMPLETED:set'
            else:
                command = [shell, '-ic']
                check = source + '; test "$GENT_HOOK_PROOF" = preserved; or exit 10; command -v gent; '
                check += "complete -C 'gent node name s' | string match -qr '^set(\\t|$)'; or exit 11; printf 'COMPLETED:set\\n'"
            result = subprocess.run(command + [check], env=env, cwd=root, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            assert str(binary) in result.stdout and 'COMPLETED:set' in result.stdout, (result.stdout, result.stderr)
            if name == 'zsh':
                zsh_tab_completion(shell, env, root)
            # Noninteractive scripts and missing executables leave PATH alone.
            no_path = source + '; test "$PATH" = /usr/bin:/bin'
            flags = ['--noprofile', '--norc', '-c'] if name == 'bash' else ['-dfc']
            if name == 'fish':
                literal = "'" + str(directory).replace('\\', '\\\\').replace("'", "\\'") + "'"
                no_path = 'set -l gent_before_path $PATH; ' + source
                no_path += '; test (string join : -- $PATH) = (string join : -- $gent_before_path); and not contains -- ' + literal + ' $PATH'
                flags = ['-N', '-c']
            subprocess.run([shell, *flags, no_path], env=env, cwd=root, capture_output=True, check=True, timeout=15)
            gone = binary.with_name('temporarily-missing')
            binary.rename(gone)
            try:
                subprocess.run(command + [no_path], env=env, cwd=root, capture_output=True, check=True, timeout=15)
            finally:
                gone.rename(binary)
            cli('hooks', 'remove', *suffix)
            assert rc.read_text() == original
            cli('hooks', 'uninstall', *suffix)
            assert rc.read_text() == original
            print(f'PASS: {name} concurrent install, startup, nested completion, literal paths, noninteractive/missing-binary guards, and removal', flush=True)
        assert not (root / 'PWNED').exists() and not state.exists()


if __name__ == '__main__':
    main()
