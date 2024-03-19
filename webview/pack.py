import pathlib
import subprocess

path2pyinstaller = pathlib.Path(r'..\..\venv\Scripts\pyinstaller.exe').resolve()

subprocess.run([
    path2pyinstaller, '-F', '-w',
    '--distpath', '../',
    '-n', 'GbfrAct',
    'main.py'
])
