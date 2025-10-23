import tkinter as tk
from tkinter import messagebox
from manual.dns_lookup_manual import dns_lookup

def perform_lookup():
    domain = entry.get().strip()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain name.")
        return
    dns_lookup(domain)

root = tk.Tk()
root.title("DNS Lookup Tool")
root.geometry("400x150")

tk.Label(root, text="Enter Domain Name:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=40)
entry.pack()
tk.Button(root, text="Lookup", command=perform_lookup, bg="#4CAF50", fg="white").pack(pady=10)

root.mainloop()
