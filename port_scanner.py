Python 3.13.7 (tags/v3.13.7:bcee1c3, Aug 14 2025, 14:15:11) [MSC v.1944 64 bit (AMD64)] on win32
Enter "help" below or click "Help" above for more information.
#!/usr/bin/env python3
# network_security_toolkit.py
# برنامج: Network Security Toolkit (Port Scanner + Vulnerability Checker + Password Tester)
# Author: Tagalser 

import socket
import threading
import re
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import datetime

# محاولة استيراد nmap و requests (اختياريان)
try:
    import nmap
    HAVE_NMAP = True
except Exception:
    HAVE_NMAP = False

try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

# لستة البورتات الحساسة الشائعة
DANGEROUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
}

# -------------------------
# دوال الفحص الأساسية
# -------------------------
def resolve_host(host):
    """تحويل دومين لـ IP (إن أمكن)"""
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        raise RuntimeError(f"تعذر حلّ اسم النطاق: {e}")

def single_scan(ip_addr, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip_addr, port))
        s.close()
        return True
    except Exception:
        return False

def scan_ports(ip_or_host, start_port, end_port, timeout=0.4, workers=200, progress_callback=None):
    """يمسح البورتات بسرعة باستخدام ThreadPoolExecutor"""
    try:
        ip_addr = resolve_host(ip_or_host)
    except Exception as e:
        raise

    open_ports = []
    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    checked = 0

    def task(port):
        nonlocal checked
        ok = single_scan(ip_addr, port, timeout)
        checked += 1
        if progress_callback:
            progress_callback(port, ok, checked, total)
        return port if ok else None

    with ThreadPoolExecutor(max_workers=min(workers, total)) as ex:
        futures = {ex.submit(task, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)

    return sorted(open_ports)

def check_vulnerabilities(open_ports):
    """يرجع لستة البورتات الحساسة المكتشفة"""
    risks = []
    for p in open_ports:
        if p in DANGEROUS_PORTS:
            risks.append((p, DANGEROUS_PORTS[p]))
    return risks

# -------------------------
# Password strength
# -------------------------
def password_strength(password):
    score = 0
    notes = []

    if len(password) >= 8:
        score += 1
    else:
        notes.append("طول كلمة السر أقل من 8 أحرف")

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        notes.append("مافي حرف كبير")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        notes.append("مافي حرف صغير")

    if re.search(r"\d", password):
        score += 1
    else:
        notes.append("مافي رقم")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=;\[\]\\\/'`~]", password):
        score += 1
    else:
        notes.append("مافي رمز خاص (مثال: @,#,$,!)")

    # تقييم
    if score >= 5:
        level = "قوية 💪"
    elif 3 <= score < 5:
        level = "متوسطة ⚠️"
    else:
        level = "ضعيفة ❌"

    return {"score": score, "level": level, "notes": notes}

# -------------------------
# واجهة المستخدم (Tkinter)
# -------------------------
class App:
    def _init_(self, root):
        self.root = root
        root.title("Network Security Toolkit - Taj")
        root.geometry("760x520")

        # Notebook tabs
        self.tabControl = ttk.Notebook(root)
        self.tab_scan = ttk.Frame(self.tabControl)
        self.tab_pass = ttk.Frame(self.tabControl)

        self.tabControl.add(self.tab_scan, text='Port Scanner')
        self.tabControl.add(self.tab_pass, text='Password Tester')
        self.tabControl.pack(expand=1, fill="both")

        self.build_scan_tab()
        self.build_pass_tab()

    def build_scan_tab(self):
        frame_top = ttk.Frame(self.tab_scan, padding=8)
        frame_top.pack(fill="x")

        ttk.Label(frame_top, text="IP / Host:").grid(row=0, column=0, sticky="w")
        self.entry_host = ttk.Entry(frame_top, width=30)
        self.entry_host.grid(row=0, column=1, padx=6, sticky="w")
        self.entry_host.insert(0, "127.0.0.1")

        ttk.Label(frame_top, text="Start Port:").grid(row=0, column=2, sticky="w")
        self.entry_start = ttk.Entry(frame_top, width=8)
        self.entry_start.grid(row=0, column=3, padx=6, sticky="w")
        self.entry_start.insert(0, "1")

        ttk.Label(frame_top, text="End Port:").grid(row=0, column=4, sticky="w")
        self.entry_end = ttk.Entry(frame_top, width=8)
        self.entry_end.grid(row=0, column=5, padx=6, sticky="w")
        self.entry_end.insert(0, "1024")

        ttk.Label(frame_top, text="Timeout(s):").grid(row=1, column=0, sticky="w", pady=6)
        self.entry_timeout = ttk.Entry(frame_top, width=8)
        self.entry_timeout.grid(row=1, column=1, sticky="w")
        self.entry_timeout.insert(0, "0.4")

        self.btn_scan = ttk.Button(frame_top, text="Start Scan", command=self.start_scan_thread)
        self.btn_scan.grid(row=1, column=3, pady=6)

        self.btn_save = ttk.Button(frame_top, text="Save Results", command=self.save_results)
        self.btn_save.grid(row=1, column=4, pady=6)

        # نتائج المسح
        self.txt_results = scrolledtext.ScrolledText(self.tab_scan, wrap=tk.WORD, height=20)
        self.txt_results.pack(fill="both", padx=8, pady=8, expand=True)
        self.txt_results.insert(tk.END, "جاهز للمسح.\n")
        self.txt_results.configure(state='disabled')

    def append_text(self, text):
        self.txt_results.configure(state='normal')
        self.txt_results.insert(tk.END, text + "\n")
        self.txt_results.see(tk.END)
        self.txt_results.configure(state='disabled')

    def progress_callback(self, port, ok, checked, total):
        # تستدعى من ثريد الفحص؛ نحدّث الـ GUI بطريقة آمنة عبر after
        def _update():
            if ok:
                self.append_text(f"[OPEN] Port {port}")
            # يمكن إظهار تقدم سريع (مؤقت):
            if checked % 50 == 0 or checked == total:
                self.append_text(f"-- Checked {checked}/{total} ports --")
        self.root.after(1, _update)

    def start_scan_thread(self):
        host = self.entry_host.get().strip()
        try:
            start = int(self.entry_start.get().strip())
            end = int(self.entry_end.get().strip())
            timeout = float(self.entry_timeout.get().strip())
        except Exception:
            messagebox.showerror("خطأ", "تأكد من مدخلات البورت/الوقت صحيحة.")
            return

        if start < 1 or end < start:
            messagebox.showerror("خطأ", "نطاق البورت خطأ.")
            return

        # تعطيل الزر أثناء الفحص
        self.btn_scan.config(state='disabled')
        self.txt_results.configure(state='normal')
        self.txt_results.delete(1.0, tk.END)
        self.txt_results.insert(tk.END, f"Starting scan: {host} ports {start}-{end}\n")
        self.txt_results.configure(state='disabled')

        def runner():
            try:
                open_ports = scan_ports(host, start, end, timeout=timeout, workers=200, progress_callback=self.progress_callback)
                self.root.after(1, lambda: self.append_text(f"Scan finished. Open ports: {open_ports}"))
                risks = check_vulnerabilities(open_ports)
                if risks:
                    for p, name in risks:
                        self.root.after(1, lambda p=p, name=name: self.append_text(f"!!! WARNING: Port {p} ({name}) is open and may be risky"))
                else:
                    self.root.after(1, lambda: self.append_text("No well-known risky ports detected."))
            except Exception as e:
                self.root.after(1, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(1, lambda: self.btn_scan.config(state='normal'))

        t = threading.Thread(target=runner, daemon=True)
        t.start()

    def save_results(self):
        content = self.txt_results.get(1.0, tk.END)
        if not content.strip():
            messagebox.showinfo("Info", "لا توجد نتائج للحفظ.")
            return
        fname = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")], initialfile=f"scan_results_{int(time.time())}.txt")
        if fname:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Saved to {fname}")
... 
...     def build_pass_tab(self):
...         frm = ttk.Frame(self.tab_pass, padding=12)
...         frm.pack(fill="x")
... 
...         ttk.Label(frm, text="Enter password:").grid(row=0, column=0, sticky="w")
...         self.entry_pw = ttk.Entry(frm, show="*", width=40)
...         self.entry_pw.grid(row=0, column=1, padx=6)
... 
...         self.btn_check_pw = ttk.Button(frm, text="Check Strength", command=self.check_password_ui)
...         self.btn_check_pw.grid(row=0, column=2, padx=6)
... 
...         self.lbl_result = ttk.Label(frm, text="")
...         self.lbl_result.grid(row=1, column=0, columnspan=3, pady=8, sticky="w")
... 
...         self.txt_pw_notes = scrolledtext.ScrolledText(self.tab_pass, wrap=tk.WORD, height=18)
...         self.txt_pw_notes.pack(fill="both", padx=8, pady=8, expand=True)
...         self.txt_pw_notes.insert(tk.END, "أدخل كلمة السر واضغط Check Strength\n")
...         self.txt_pw_notes.configure(state='disabled')
... 
...     def check_password_ui(self):
...         pw = self.entry_pw.get()
...         if not pw:
...             messagebox.showwarning("Warning", "ادخل كلمة السر أولاً")
...             return
...         res = password_strength(pw)
...         self.lbl_result.config(text=f"Score: {res['score']} — {res['level']}")
...         self.txt_pw_notes.configure(state='normal')
...         self.txt_pw_notes.delete(1.0, tk.END)
...         self.txt_pw_notes.insert(tk.END, f"التقييم: {res['level']}\nنقاط: {res['score']}\n\n")
...         if res['notes']:
...             self.txt_pw_notes.insert(tk.END, "ملاحظات لتحسين كلمة السر:\n")
...             for n in res['notes']:
...                 self.txt_pw_notes.insert(tk.END, f"- {n}\n")
...         else:
...             self.txt_pw_notes.insert(tk.END, "كلمة السر تبدو قويّة 👍\n")
...         self.txt_pw_notes.configure(state='disabled')
... 
... if _name_ == "_main_":
...     root = tk.Tk()
...     app = App(root)
