"""
Script Name: PasswordGenerator.py
Author: Justin Andrews
Version: 1.0
Date Created: 4/11/24
Last Updated: 4/12/24

Description:
    This Python script generates randomly generated passwords with a graphical user interface.
    Features include:
    - Customizable password length (12-32 characters)
    - Option to include letters and symbols
    - Unique random seed generation through user interaction

TODO:
    - Comment code and "de-gremlin" it.
    - Have upper/lowercase letters in separate lists to ensure a fair distribution of both.
    - Refactor and modularize code.

Potential Features:
    - Password strength checker
    - Option to set a reminder to change the password after a user-defined amount of time
    - (Possibly use a batch file in startup, but consider intrusiveness)

GUI Parameters Start:
"launch": true
GUI Parameters End:
Note: This script runs with a graphical user interface. The 'launch' parameter
      indicates that the script should be executed directly to start the GUI.
"""
import tkinter as tk
from tkinter import ttk
import random
from datetime import datetime

letters = [
    'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p',
    'q', 'r', 's', 't',
    'u', 'v', 'w', 'x',
    'y', 'z',
    'A', 'B', 'C', 'D',
    'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X',
    'Y', 'Z'
]

symbols = ["!", "@", "$", "#", "%", "^", "&", "*",
           "-", "_", "+", "=", "{", "}", "[", "]",
           "\\", "|", ":", ";", "\"", "'"]


# Create root and set it's attributes.
root = tk.Tk()
root.title('Password Generator')
root.geometry('500x250')
root.resizable(False, False)

# StringVar to control widgets being disabled.
widget_state = tk.StringVar()
widget_state.set('disabled')

# Variable for user random seed.
user_rand = tk.DoubleVar()


# Generate a random number, then hash it.
# The hashing is used to create a baseline length.
def gen_random_num():
    rand_hash = hash(str(random.randint(0, 1000)))
    if rand_hash < 0:
        rand_hash *= -1
    return rand_hash


# Create a frame in the root.
frame = ttk.Frame(root)

# TopLevel window for user generated random seed.
rand_frame = tk.Toplevel(frame)
rand_frame.title('Random Number Seed Generater')
rand_frame.geometry('400x400')
rand_frame.withdraw()

# Vars. Need to be reorganized.
password = []
password_letters = []
index_list = []
display_text = tk.StringVar()
letter_bool = tk.BooleanVar()
symbol_bool = tk.BooleanVar()
pass_length = tk.IntVar()

# Function to populate the array with random numbers, letter, or symbols.


def generate_pass():

    # Repeat Vars. Fix
    password = []
    password_letters = []
    hash_val = str(gen_random_num())
    hash_arr = []

    # Iterated through the hash and populate the array with it's contents.
    for i in hash_val:
        hash_arr.append(i)

    # Shorten the password if needed.
    if len(hash_arr) > pass_length.get():
        while len(hash_arr) > pass_length.get():
            hash_arr.pop(-1)

    # Lengthen the password if needed.
    if len(hash_arr) < pass_length.get():
        hash_val = str(gen_random_num())
        for i in hash_val:
            if len(hash_arr) < pass_length.get():
                hash_arr.append(i)

    # Makes numbers single digit.
    for i in hash_arr:
        temp_pass = float(i) * (user_rand.get() * .1) % 10
        password.append(int(temp_pass))

    # If Letter checkbox is checked: Add letters.
    if letter_bool.get():
        password_letters = add_letters(password)
        display_text.set(password_letters)

    # If symbols checkbox is check: Add symbols.
    if symbol_bool.get():
        password_symbols = add_symbols(password)
        display_text.set(password_symbols)

    # If neither are checked, return the number pass
    else:
        display_text.set(password)

# Function to add letters to the password.


def add_letters(password):

    # Spread of how many letters to add.
    symbol_and_char_spread = random.randint(int(len(password) / 4),
                                            int(len(password) / 2))
    i = 0
    index_template = []

    # Make a an array of the index of the password array.
    # I did it this way to prevent hanging in generating numbers
    # for random index locations to be replaced with letters.
    while i != len(password):
        index_template.append(i)
        i += 1
    i = 0

    # Get the random index and appending it index_list
    # to be used for replacing numbers with letters.
    while i != symbol_and_char_spread:
        index = random.randint(0, (len(index_template) - 1))
        index_list.append(index_template[index])

        # Remove the index from the index template to prevent
        # the same index being used twice.
        index_template.pop(index)
        i += 1

    # Replace numbers with letters.
    for i in range(symbol_and_char_spread):
        rand_letter_index = random.randint(0, len(letters) - 1)
        password[index_list[i]] = letters[rand_letter_index]
    # Clear the index_list so it can be used again
    # without restarting the script.
    index_list.clear()
    return password

# Function to add symbols to the password.


def add_symbols(password):
    # Spread of how many symbols to add.
    symbol_and_char_spread = random.randint(int(len(password) / 4),
                                            int(len(password) / 2))
    i = 0
    index_template = []

    # Make a an array of the index of the password array.
    # I did it this way to prevent hanging in generating numbers for
    # random index locations to be replaced with symbols.
    while i != len(password):
        index_template.append(i)
        i += 1
    i = 0

    # Get the random index and appending it index_list
    # to be used for replacing numbers with symbols.
    while i != symbol_and_char_spread:
        index = random.randint(0, (len(index_template) - 1))
        index_list.append(index_template[index])
        index_template.pop(index)
        i += 1

    # Replace numbers with symbols.
    for i in range(symbol_and_char_spread):
        rand_symbol_index = random.randint(0, len(symbols) - 1)
        password[index_list[i]] = symbols[rand_symbol_index]

    # Clear the index_list so it can be used again
    # without restarting the script.
    index_list.clear()
    return password


# Beings TopLevel window to top and grabs its focus.
def set_window_state():
    rand_frame.state(newstate='normal')
    rand_frame.grab_set()
    rand_frame.focus()


def enable_gui(seed):
    user_rand.set(seed)
    not_rand_label_text.set('Seed Generated: ' + f'{user_rand.get(): .2f}' + '. Feel free to generate again.')
    for i in frame_widget_list:
        i.configure(state='active')


# String var letting the user know to generate the random seed.
not_rand_label_text = tk.StringVar()
not_rand_label_text.set(
    "You must generate a random seed using the" +
    "button at the top of the window.")

# Label for letting the users know to generate random seed.
not_rand_label = tk.Label(frame, textvariable=not_rand_label_text)

# Button to generate random seed.
rand_button = tk.Button(frame, text="Generate Seed")
rand_button.configure(command=set_window_state)

# Slider for password length.
slider_label = tk.Label(frame, text="Password Size:")

pass_length_slider = tk.Scale(frame, from_=12, to=32,
                              orient='horizontal', variable=pass_length,
                              state='disabled')

# Checkboxes to include letters and symbols.
letters_check = tk.Checkbutton(frame, text="Include letters",
                               variable=letter_bool,
                               onvalue=True, offvalue=False,
                               state='disabled')

symbols_check = tk.Checkbutton(frame, text="Include Symbols",
                               variable=symbol_bool,
                               onvalue=True, offvalue=False,
                               state='disabled')

# Button to generate password.
generate_pass_button = ttk.Button(
    frame, text='Generate Password', state='disabled')
generate_pass_button.configure(command=generate_pass)

# Entry to display password. Used entry so it can be copied by the user.
display_pass = ttk.Entry(frame, textvariable=display_text,
                         state='readonly', width=60, justify='center')

frame_widget_list = [pass_length_slider, letters_check, symbols_check, generate_pass_button]

# Frame grid configuration.
not_rand_label.grid(column=0, row=0, sticky="E")
rand_button.grid(column=0, row=1, stick='W')
slider_label.grid(column=0, row=2, sticky='W')
pass_length_slider.grid(column=0, row=3, sticky='W')
letters_check.grid(column=0, row=4, sticky='w')
symbols_check.grid(column=0, row=5, sticky='w')
generate_pass_button.grid(column=0, row=6, sticky='w')
display_pass.grid(column=0, row=7, columnspan=4, sticky='s')

frame.grid(padx=10, pady=10)

rand_button_disabled_list = []
rand_button_times = []

# Function that generates the random seed using buttons.


def rand_button_click(button):

    # Disbaled buttons once clicked and add it to a list to keep track of
    # which buttons are disbaled.
    button.config(state='disabled')
    rand_button_disabled_list.append(button)

    # Get the current time and turn it into integers that are good for the
    # summation and averaging for the random seed.
    current_time = datetime.now()
    current_microsec = current_time.microsecond
    rand_button_times.append(current_microsec // 11000)

    # Checks if all buttons are disabled and then closes the window,
    # and brings focus back to the main window.
    if len(rand_button_disabled_list) == 9:
        rand_frame.withdraw()
        frame.grab_set()
        frame.focus()

        # Calcs the average time between button presses.
        average_time = sum(rand_button_times) / len(rand_button_times)

        enable_gui(average_time)
        rand_button_times.clear()
        average_time = 0
        for i in rand_button_disabled_list:
            i.configure(state='active')
        rand_button_disabled_list.clear()


# Label to explain the purpose of the TopLevel window.
rand_label = tk.Label(rand_frame,
                      text="Click all of the buttons to create a random seed.")

# Button for TopLevel window.
b1 = tk.Button(rand_frame, text="Button1",
               command=lambda: rand_button_click(b1))
b2 = tk.Button(rand_frame, text="Button2",
               command=lambda: rand_button_click(b2))
b3 = tk.Button(rand_frame, text="Button3",
               command=lambda: rand_button_click(b3))
b4 = tk.Button(rand_frame, text="Button4",
               command=lambda: rand_button_click(b4))
b5 = tk.Button(rand_frame, text="Button5",
               command=lambda: rand_button_click(b5))
b6 = tk.Button(rand_frame, text="Button6",
               command=lambda: rand_button_click(b6))
b7 = tk.Button(rand_frame, text="Button7",
               command=lambda: rand_button_click(b7))
b8 = tk.Button(rand_frame, text="Button8",
               command=lambda: rand_button_click(b8))
b9 = tk.Button(rand_frame, text="Button9",
               command=lambda: rand_button_click(b9))

# Grid Configuration for TopLevel window.
rand_label.grid(column=0, row=0, columnspan=3, sticky="nsew")
b1.grid(column=0, row=1, sticky="nsew", padx=5, pady=5)
b2.grid(column=1, row=1, sticky="nsew", padx=5, pady=5)
b3.grid(column=2, row=1, sticky="nsew", padx=5, pady=5)
b4.grid(column=0, row=2, sticky="nsew", padx=5, pady=5)
b5.grid(column=1, row=2, sticky="nsew", padx=5, pady=5)
b6.grid(column=2, row=2, sticky="nsew", padx=5, pady=5)
b7.grid(column=0, row=3, sticky="nsew", padx=5, pady=5)
b8.grid(column=1, row=3, sticky="nsew", padx=5, pady=5)
b9.grid(column=2, row=3, sticky="nsew", padx=5, pady=5)

rand_frame.rowconfigure((0, 1, 2, 3), weight=1)
rand_frame.columnconfigure((0, 1, 2), weight=1)


root.mainloop()