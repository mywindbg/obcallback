import os
import subprocess
import shutil
import argparse

class Paths:
    @staticmethod
    def LogFile():
        return os.path.normcase("//vmware-host/Shared Folders/SharedFolder/obcallback/build.log")

    @staticmethod
    def MSBuild():
        return os.path.normcase("C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/MSBuild.exe")

    @staticmethod
    def OBCallBackBasePath():
        return os.path.normcase("//vmware-host/Shared Folders/SharedFolder/obcallback")

    @staticmethod
    def OBCallBackSln():
        return os.path.normcase(Paths.OBCallBackBasePath() + "/obcallback.sln")

    @staticmethod
    def DirsToClean():
        return [ Paths.OBCallBackBasePath() + "/control/x64", Paths.OBCallBackBasePath() + "/driver/x64" ]

    @staticmethod
    def OBCallBackControlExe():
        return os.path.normcase(Paths.OBCallBackBasePath() + "/control/x64/Debug/ObCallbackTestCtrl.exe")

def BuildSolution():
    build_invocation_args = [ Paths.MSBuild(), Paths.OBCallBackSln()]
    with open(Paths.LogFile(), "w+") as f:
        subprocess.run(build_invocation_args, shell=True, check=True, stdout=f, stderr=f)

def Clean():
    for dir in Paths.DirsToClean() :
        shutil.rmtree(os.path.normcase((dir)))

def Run(command, cmd_args=[]):
    with open(Paths.LogFile(), "a") as f:
        args = [ Paths.OBCallBackControlExe(), command ] + cmd_args
        print("Run: {}".format(args))
        subprocess.run(args, shell=True, check=True, stdout=f, stderr=f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--task', type=str, choices=["build", "clean", "install", "uninstall", "deprotect", "name", "reject"], default="build")
    parser.add_argument('--process', type=str, default="notepad", required=False)
    args = parser.parse_args()
    print("Task => {}".format(args.task))

    print('Script to build the driver!')

    if args.task == "build":
        BuildSolution()
    elif args.task == "clean":
        Clean()
    elif args.task == "install":
        Run("-install")
    elif args.task == "uninstall":
        Run("-uninstall")
    elif args.task == "deprotect":
        Run("-deprotect")
    elif args.task == "name":
        Run("-name", [args.process])
    elif args.task == "reject":
        Run("-reject", [args.process])
