import re
import tkinter as tk
from tkinter import ttk
import string
import math
import requests
import hashlib

# -------------------- Password Strength Checks -------------------- #
def check_password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()_+\-=[\]{};':\"\\|,.<>\/?]", password):
        score += 1

    if score == 5:
        return "STRONG", "#00ff00", 100, "🟢 Solid! This one’s a fortress."
    elif score >= 3:
        return "MODERATE", "#ffaa00", 60, "🟠 Not bad — try adding more chaos."
    else:
        return "WEAK", "#ff0033", 30, "🔴 Weak sauce. Mix it up, hacker."

# -------------------- Entropy Meter -------------------- #
def calculate_entropy(password):
    char_set_size = sum([ 
        len(string.ascii_lowercase) if any(c.islower() for c in password) else 0,
        len(string.ascii_uppercase) if any(c.isupper() for c in password) else 0,
        len(string.digits) if any(c.isdigit() for c in password) else 0,
        len(string.punctuation) if any(c in string.punctuation for c in password) else 0
    ])
    return len(password) * math.log2(max(char_set_size, 1))

# -------------------- Crack Time Estimator -------------------- #
def estimate_crack_time(password):
    entropy = calculate_entropy(password)
    # Estimate the number of guesses per second (1 million guesses per second as an example)
    guesses_per_second = 10**6
    # Total number of guesses (2^entropy)
    total_guesses = 2 ** entropy
    # Time in seconds to crack the password
    time_seconds = total_guesses / guesses_per_second
    
    # Convert time to years, months, days, hours, minutes, and seconds
    years = time_seconds // (60 * 60 * 24 * 365.25)
    time_seconds %= (60 * 60 * 24 * 365.25)
    months = time_seconds // (60 * 60 * 24 * 30)
    time_seconds %= (60 * 60 * 24 * 30)
    days = time_seconds // (60 * 60 * 24)
    time_seconds %= (60 * 60 * 24)
    hours = time_seconds // (60 * 60)
    time_seconds %= (60 * 60)
    minutes = time_seconds // 60
    seconds = time_seconds % 60
    
    return f"{int(years)} years, {int(months)} months, {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

# -------------------- HIBP Integration -------------------- #
def check_pwned(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if res.status_code != 200:
            return "❓ Could not verify breaches."
        hashes = (line.split(":") for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"☠️ Found in {count} breaches!"
        return "✅ Not found in known breaches."
    except:
        return "❓ Network error checking breach."

# -------------------- Update Everything -------------------- #
def update_feedback(event=None):
    pwd = entry.get()
    strength, color, percent, feedback = check_password_strength(pwd)
    result_label.config(text=f"Strength: {strength}", fg=color)
    feedback_label.config(text=feedback)
    strength_bar['value'] = percent
    style.configure("TProgressbar", troughcolor="#2c2c2c", background=color)

    # Terminal output
    terminal_output.delete("1.0", tk.END)
    terminal_output.insert(tk.END, f"[*] Analyzing password...\n")
    terminal_output.insert(tk.END, f"[+] Length: {len(pwd)}\n")
    terminal_output.insert(tk.END, f"[+] Entropy: {calculate_entropy(pwd):.2f} bits\n")
    terminal_output.insert(tk.END, f"[+] Strength: {strength}\n")
    terminal_output.insert(tk.END, f"[+] Feedback: {feedback}\n")

    # Crack time estimate
    crack_time = estimate_crack_time(pwd)
    terminal_output.insert(tk.END, f"[+] Estimated crack time: {crack_time}\n")

    # HIBP Check
    if len(pwd) > 4:  # Only check passwords longer than 4 characters
        hibp_result = check_pwned(pwd)
        terminal_output.insert(tk.END, f"[!] HIBP: {hibp_result}\n")
        feedback_label.config(text=f"{feedback}\n{hibp_result}")

    # Update ring canvas
    ring_canvas.delete("all")
    draw_entropy_ring(ring_canvas, percent, color)

# -------------------- Visual Ring -------------------- #
def draw_entropy_ring(canvas, percent, color):
    angle = int(360 * percent / 100)
    glow_color = color if percent == 100 else ""
    canvas.create_oval(10, 10, 110, 110, outline="#333", width=8)
    canvas.create_arc(10, 10, 110, 110, start=90, extent=-angle, outline=color, width=8, style="arc")
    if percent == 100:
        canvas.create_oval(14, 14, 106, 106, outline=color, width=2)

# -------------------- Toggle Password -------------------- #
def toggle_password():
    if entry.cget("show") == "*":
        entry.config(show="")
        toggle_btn.config(text="Hide Password")
    else:
        entry.config(show="*")
        toggle_btn.config(text="Show Password")

# -------------------- GUI Setup -------------------- #
app = tk.Tk()
app.title("BruteBreaker - Password Analyzer")
app.configure(bg="#0d0d0d")
app.geometry("460x620")
app.resizable(False, False)
style = ttk.Style()
style.theme_use('default')

main_frame = tk.Frame(app, bg="#0d0d0d")
main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

title_label = tk.Label(main_frame, text="🧠 BruteBreaker", font=("Consolas", 18, "bold"), bg="#0d0d0d", fg="#00fff7")
title_label.pack(pady=(10, 5))

subtitle_label = tk.Label(main_frame, text="Live password analysis + HIBP breach check", font=("Consolas", 10), bg="#0d0d0d", fg="#aaa")
subtitle_label.pack(pady=(0, 20))

entry = tk.Entry(main_frame, show="*", font=("Consolas", 12), width=30, bd=2, fg="#00ffcc", bg="#1c1c1c", insertbackground="#00ffcc")
entry.pack(pady=(0, 10))
entry.bind("<KeyRelease>", update_feedback)

toggle_btn = tk.Button(main_frame, text="Show Password", font=("Consolas", 10), command=toggle_password, bg="#1c1c1c", fg="#00ffcc", bd=0)
toggle_btn.pack(pady=(0, 10))

strength_bar = ttk.Progressbar(main_frame, length=300, mode='determinate')
strength_bar.pack(pady=(10, 10))

result_label = tk.Label(main_frame, text="", font=("Consolas", 14, "bold"), bg="#0d0d0d")
result_label.pack(pady=(10, 5))

feedback_label = tk.Label(main_frame, text="", font=("Consolas", 10), wraplength=360, bg="#0d0d0d", fg="#aaaaaa", justify="center")
feedback_label.pack(pady=(5, 10))

ring_canvas = tk.Canvas(main_frame, width=120, height=120, bg="#0d0d0d", highlightthickness=0)
ring_canvas.pack(pady=5)

terminal_output = tk.Text(main_frame, height=10, width=55, bg="#111", fg="#0f0", font=("Consolas", 9), border=0)
terminal_output.pack(pady=10)

footer = tk.Label(main_frame, text="🔒 Stay Secure, Stay Sharp. #BruteBreaker", font=("Consolas", 9), bg="#0d0d0d", fg="#444")
footer.pack(pady=(5, 5))

app.mainloop()
