import os

commands = [
    r"python MainScripts\DNSZoneTranfer.py zonetransfer.me nsztm1.digi.ninja",
    r"python MainScripts\HTTPHeader.py https://demo.testfire.net/",
    r"python MainScripts\PingScanPy.py 192.168.56.0/24 -t 10 --debug",
    r"python MainScripts\TCPScan.py --ipaddr 192.168.56.101 --start-port 1 --end-port 1500 --timeout 2 --max-attempts 2",
    r"python MainScripts\CrossSiteScripting.py https://xss-game.appspot.com/level1/frame"
    r"python MainScripts\SQLInjection.py https://demo.testfire.net/login.jsp",
    r"python MainScripts\WebDirectoryBruteForcer.py",
    r"python MainScripts\Hash.py TestScripts\HashFile1.txt",
    r"python MainScripts\PasswordGenerater.py",
    r"python SimpleGui\PortablePenTestGUI.py",
]


for script in commands:
    temp = input(f'Press enter to run or enter "skip" to skip: {script} ')
    if temp == "skip":
        pass
    else:
        print(os.system(f"cmd /c {script}"))
