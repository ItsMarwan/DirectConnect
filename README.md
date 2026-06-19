# 🎯 DirectConnect

> A **secure**, **zero-cloud-storage**, direct **peer-to-peer** file sharing tool that works globally. The website is entirely static (perfect for GitHub Pages), and the local Python companion serves files securely from your PC.

## How to Compile into a Single EXE
> [!NOTE]
> You can compile share.py into a portable .exe file so your users can run it instantly without needing Python installed.

1. Install PyInstaller:
```bash
pip install pyinstaller
```

2. Compile the script:
```bash
pyinstaller --onefile --name DirectConnect share.py
```

3. Once finished, you will find DirectConnect.exe inside the newly created dist/ directory. You can distribute this single executable directly to your users!

> [!TIP]
> ## How it works

1. **Host**: Run the DirectConnect executable on your PC.

2. **Secure**: Enter any session password and provide the file you wish to share.

3. **P2P Channel**: The companion launches your browser, which hooks up with a secure WebRTC signaling gateway.

4. **Share**: Copy the generated global link and send it to your recipient.

5. **Download**: The recipient opens the link, inputs the password, and streams the file directly from your machine.

## Virus Total Scan
> [!WARNING]
> Still havent Scanned it yet. source code is here if you dont trust the exe
