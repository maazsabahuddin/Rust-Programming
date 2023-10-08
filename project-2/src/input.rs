// Constants, structs, and arrays derived from /linux/include/linux/input.h

const MAX_KEYS: usize = 112;  // Maximum number of keys

const EV_KEY: u16 = 1;  // Event type for key events

const KEY_RELEASE: i32 = 0;  // Key release event value
const KEY_PRESS: i32 = 1;    // Key press event value

const KEY_LEFTSHIFT: u16 = 42;    // Key code for left shift
const KEY_RIGHTSHIFT: u16 = 43;   // Key code for right shift

// Structure representing an input event
#[derive(Debug)]
#[repr(C)]
pub struct InputEvent {
    tv_sec: isize, // from timeval struct
    tv_usec: isize, // from timeval struct
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

// Unknown key string
const UK: &str = "<UK>";

// Array of key names
const KEY_NAMES: [&str; MAX_KEYS] = [
    UK, "<ESC>",
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=",
    "<Backspace>", "<Tab>",
    "q", "w", "e", "r", "t", "y", "u", "i", "o", "p",
    "[", "]", "<Enter>", "<LCtrl>",
    "a", "s", "d", "f", "g", "h", "j", "k", "l", ";",
    "'", "`", "<LShift>",
    "\\", "z", "x", "c", "v", "b", "n", "m", ",", ".", "/",
    "<RShift>",
    "<KP*>",
    "<LAlt>", " ", "<CapsLock>",
    "<F1>", "<F2>", "<F3>", "<F4>", "<F5>", "<F6>", "<F7>", "<F8>", "<F9>", "<F10>",
    "<NumLock>", "<ScrollLock>",
    "<KP7>", "<KP8>", "<KP9>",
    "<KP->",
    "<KP4>", "<KP5>", "<KP6>",
    "<KP+>",
    "<KP1>", "<KP2>", "<KP3>", "<KP0>",
    "<KP.>",
    UK, UK, UK,
    "<F11>", "<F12>",
    UK, UK, UK, UK, UK, UK, UK,
    "<KPEnter>", "<RCtrl>", "<KP/>", "<SysRq>", "<RAlt>", UK,
    "<Home>", "<Up>", "<PageUp>", "<Left>", "<Right>", "<End>", "<Down>",
    "<PageDown>", "<Insert>", "<Delete>",
];

// Array of key names when Shift key is pressed
const SHIFT_KEY_NAMES: [&str; MAX_KEYS] = [
    UK, "<ESC>",
    "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+",
    "<Backspace>", "<Tab>",
    "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P",
    "{", "}", "<Enter>", "<LCtrl>",
    "A", "S", "D", "F", "G", "H", "J", "K", "L", ":",
    "\"", "~", "<LShift>",
    "|", "Z", "X", "C", "V", "B", "N", "M", "<", ">", "?",
    "<RShift>",
    "<KP*>",
    "<LAlt>", " ", "<CapsLock>",
    "<F1>", "<F2>", "<F3>", "<F4>", "<F5>", "<F6>", "<F7>", "<F8>", "<F9>", "<F10>",
    "<NumLock>", "<ScrollLock>",
    "<KP7>", "<KP8>", "<KP9>",
    "<KP->",
    "<KP4>", "<KP5>", "<KP6>",
    "<KP+>",
    "<KP1>", "<KP2>", "<KP3>", "<KP0>",
    "<KP.>",
    UK, UK, UK,
    "<F11>", "<F12>",
    UK, UK, UK, UK, UK, UK, UK,
    "<KPEnter>", "<RCtrl>", "<KP/>", "<SysRq>", "<RAlt>", UK,
    "<Home>", "<Up>", "<PageUp>", "<Left>", "<Right>", "<End>", "<Down>",
    "<PageDown>", "<Insert>", "<Delete>",
];

// Converts a key code to its ASCII representation
// Some unprintable keys like escape are printed as a name between angled brackets, i.e., <ESC>pub fn get_key_text(code: u16, shift_pressed: u8) -> &str {
    let arr = if shift_pressed != 0 {
        &SHIFT_KEY_NAMES
    } else {
        &KEY_NAMES
    };

    if code < MAX_KEYS as u16 {
        arr[code as usize]
    } else {
        debug!("Unknown key: {}", code);
        UK
    }
}

// Determines whether the given key code is a shift key
pub fn is_shift(code: u16) -> bool {
    code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT
}

// Checks if the event type is a key event
pub fn is_key_event(type_: u16) -> bool {
    type_ == EV_KEY
}

// Checks if the event value represents a key press
pub fn is_key_press(value: i32) -> bool {
    value == KEY_PRESS
}

// Checks if the event value represents a key release
pub fn is_key_release(value: i32) -> bool {
    value == KEY_RELEASE
}