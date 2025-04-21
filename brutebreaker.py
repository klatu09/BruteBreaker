import re
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string
import time
import datetime
import math

# Password strength check
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
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1

    if score == 5:
        return "STRONG", "#00ff00", 100, "🟢 Solid! This one’s a fortress."
    elif score >= 3:
        return "MODERATE", "#ffaa00", 60, "🟠 Not bad — try adding more chaos."
    else:
        return "WEAK", "#ff0033", 30, "🔴 Weak sauce. Mix it up, hacker."

# Generate strong password suggestion
def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for i in range(12))
    return password

## Brute Force Time Estimation (based on password strength)
def calculate_crack_time(password):
    # Brute force time simulation based on password complexity
    # Let's assume the average attacker can try 1 million guesses per second.

    # Character sets
    lower_case = string.ascii_lowercase
    upper_case = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation
    
    # Determine password character set
    char_set_size = 0
    if any(c.islower() for c in password):
        char_set_size += len(lower_case)
    if any(c.isupper() for c in password):
        char_set_size += len(upper_case)
    if any(c.isdigit() for c in password):
        char_set_size += len(digits)
    if any(c in symbols for c in password):
        char_set_size += len(symbols)

    # Ensure char_set_size is at least 1 to avoid math domain error
    if char_set_size == 0:
        char_set_size = 1

    # Calculate password entropy (number of possible combinations)
    entropy = len(password) * math.log2(char_set_size)

    # Time to crack (in seconds)
    attempts_per_second = 10**6  # 1 million attempts per second
    time_to_crack = (2 ** entropy) / attempts_per_second  # Time to crack in seconds

    # Convert to a human-readable format (e.g., seconds, minutes, hours)
    if time_to_crack < 60:
        return f"{int(time_to_crack)} seconds"
    elif time_to_crack < 3600:
        return f"{int(time_to_crack // 60)} minutes"
    elif time_to_crack < 86400:
        return f"{int(time_to_crack // 3600)} hours"
    else:
        return f"{int(time_to_crack // 86400)} days"


# Update feedback and suggestions
def update_feedback(event=None):
    pwd = entry.get()
    strength, color, percent, feedback = check_password_strength(pwd)
    result_label.config(text=f"Strength: {strength}", fg=color)
    feedback_label.config(text=feedback)
    strength_bar['value'] = percent
    style.configure("TProgressbar", troughcolor="#2c2c2c", background=color)

    # Suggest new password if weak
    if strength == "WEAK":
        suggestion = generate_password()
        suggestion_label.config(text=f"🔑 Suggested Strong Password: {suggestion}")

    # Show estimated time to crack
    time_to_crack = calculate_crack_time(pwd)
    crack_time_label.config(text=f"Estimated time to brute-force: {time_to_crack}")

# Toggle password visibility
def toggle_password():
    if entry.cget("show") == "":
        entry.config(show="*")
        toggle_btn.config(text="👁️")
    else:
        entry.config(show="")
        toggle_btn.config(text="🙈")

# GUI Setup
app = tk.Tk()
app.title("BruteBreaker - Password Analyzer")
app.geometry("480x430")
app.resizable(False, False)
app.configure(bg="#0d0d0d")

style = ttk.Style()
style.theme_use("default")
style.configure("TProgressbar", thickness=20, troughcolor="#2c2c2c", background="#00ff00")

# Title
title = tk.Label(app, text="🧠 BruteBreaker", font=("Consolas", 18, "bold"), bg="#0d0d0d", fg="#00fff7")
subtitle = tk.Label(app, text="Real-time password analyzer by K1atu", font=("Consolas", 10), bg="#0d0d0d", fg="#555")
title.pack(pady=(12, 0))
subtitle.pack(pady=(0, 12))

# Entry frame (for toggle icon beside input)
entry_frame = tk.Frame(app, bg="#0d0d0d")
entry_frame.pack()

entry = tk.Entry(entry_frame, show="*", font=("Consolas", 12), width=30, bd=2, fg="#00ffcc", bg="#1c1c1c", insertbackground="#00ffcc")
entry.pack(side="left", padx=(10, 5))
entry.bind("<KeyRelease>", update_feedback)

toggle_btn = tk.Button(entry_frame, text="👁️", font=("Consolas", 10), command=toggle_password, bg="#1c1c1c", fg="#00ffcc", bd=0, activebackground="#333")
toggle_btn.pack(side="left")

# Strength bar
strength_bar = ttk.Progressbar(app, length=300, mode='determinate')
strength_bar.pack(pady=20)

# Result
result_label = tk.Label(app, text="", font=("Consolas", 14, "bold"), bg="#0d0d0d")
result_label.pack()

# Feedback
feedback_label = tk.Label(app, text="", font=("Consolas", 10), wraplength=360, bg="#0d0d0d", fg="#aaaaaa", justify="center")
feedback_label.pack(pady=10)

# Suggested password
suggestion_label = tk.Label(app, text="", font=("Consolas", 10, "italic"), wraplength=360, bg="#0d0d0d", fg="#00cc00", justify="center")
suggestion_label.pack(pady=10)

# Time to crack estimate
crack_time_label = tk.Label(app, text="", font=("Consolas", 10, "italic"), wraplength=360, bg="#0d0d0d", fg="#ff6347", justify="center")
crack_time_label.pack(pady=10)

# Footer
footer = tk.Label(app, text="🔒 Stay Secure, Stay Sharp. #BruteBreaker", font=("Consolas", 9), bg="#0d0d0d", fg="#444")
footer.pack(side="bottom", pady=5)

# Run app
app.mainloop()
