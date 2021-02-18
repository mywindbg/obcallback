@REM cmake -H.\ -B.\_build -DCMAKE_INSTALL_PREFIX=.\_install -DCMAKE_VERBOSE_MAKEFILE=ON
@REM cmake --build _build

python "\\vmware-host\Shared Folders\SharedFolder\obcallback\script.py" --task uninstall
python "\\vmware-host\Shared Folders\SharedFolder\obcallback\script.py" --task build
python "\\vmware-host\Shared Folders\SharedFolder\obcallback\script.py" --task install
@REM python "\\vmware-host\Shared Folders\SharedFolder\obcallback\script.py" --task name --process notepad
