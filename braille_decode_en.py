import sys, secrets, string

U = string.digits + string.ascii_lowercase  # 0-9a-z

# --- Braille maps (Grade-1) ---
# Dots numbering:  1 4
#                  2 5
#                  3 6

LETTER_TO_DOTS = {
    'a': (1,),
    'b': (1,2),
    'c': (1,4),
    'd': (1,4,5),
    'e': (1,5),
    'f': (1,2,4),
    'g': (1,2,4,5),
    'h': (1,2,5),
    'i': (2,4),
    'j': (2,4,5),
    'k': (1,3),
    'l': (1,2,3),
    'm': (1,3,4),
    'n': (1,3,4,5),
    'o': (1,3,5),
    'p': (1,2,3,4),
    'q': (1,2,3,4,5),
    'r': (1,2,3,5),
    's': (2,3,4),
    't': (2,3,4,5),
    'u': (1,3,6),
    'v': (1,2,3,6),
    'w': (2,4,5,6),
    'x': (1,3,4,6),
    'y': (1,3,4,5,6),
    'z': (1,3,5,6),
}

DOTS_TO_LETTER = {tuple(sorted(v)): k for k, v in LETTER_TO_DOTS.items()}

DIGIT_TO_LETTER = {
    '1': 'a', '2': 'b', '3': 'c', '4': 'd', '5': 'e',
    '6': 'f', '7': 'g', '8': 'h', '9': 'i', '0': 'j'
}
LETTER_TO_DIGIT = {v: k for k, v in DIGIT_TO_LETTER.items()}

# Default numeric prefix: ⠼ (3-4-5-6)
DEFAULT_NUMERIC_PREFIXES = [(3,4,5,6)]

def parse_prefixes(s: str):
    """
    Parse comma-separated dot lists, e.g. "3456,124" or "3-4-5-6".
    Returns a list of tuples of dots.
    """
    if not s:
        return DEFAULT_NUMERIC_PREFIXES
    res = []
    for tok in s.split(','):
        tok = tok.strip().replace('-', '')
        if tok == '':
            dots = tuple()
        else:
            if any(ch not in '123456' for ch in tok):
                raise ValueError(f"Invalid dot spec '{tok}'. Use digits 1-6 only.")
            dots = tuple(sorted(int(ch) for ch in tok))
        res.append(dots)
    return res

def dots_to_bits_2x3(dots: tuple[int, ...]):
    s = set(dots)
    return [
        [1 if 1 in s else 0, 1 if 4 in s else 0],
        [1 if 2 in s else 0, 1 if 5 in s else 0],
        [1 if 3 in s else 0, 1 if 6 in s else 0],
    ]

def bits_2x3_to_dots(rows_bits):
    dots = []
    if rows_bits[0][0]: dots.append(1)
    if rows_bits[0][1]: dots.append(4)
    if rows_bits[1][0]: dots.append(2)
    if rows_bits[1][1]: dots.append(5)
    if rows_bits[2][0]: dots.append(3)
    if rows_bits[2][1]: dots.append(6)
    return tuple(dots)

def validate_key(key: str):
    if not key:
        raise ValueError("Key cannot be empty.")
    key = key.lower()
    if any(ch not in U for ch in key):
        raise ValueError("Key must contain only digits 0-9 and lowercase letters a-z.")
    K = ''.join(sorted(set(key)))
    if len(K) >= len(U):
        raise ValueError("Key must not cover the entire alphabet; need both 1 and 0 sets non-empty.")
    return K

def decode(row1: str, row2: str, row3: str, key: str, numeric_prefixes: list[tuple[int, ...]]):
    K = validate_key(key)
    row1, row2, row3 = row1.strip(), row2.strip(), row3.strip()
    if not (len(row1) == len(row2) == len(row3)):
        raise ValueError("All three rows must have equal length.")
    ncols = len(row1)
    if ncols % 4 != 0:
        raise ValueError("Number of columns must be a multiple of 4 (prefix+payload per character).")
    if any(ch not in U for ch in row1+row2+row3):
        raise ValueError("Cipher rows must contain only digits 0-9 and lowercase letters a-z.")

    def char_to_bit(ch): return 1 if ch in K else 0
    rows_bits = [
        [char_to_bit(ch) for ch in row1],
        [char_to_bit(ch) for ch in row2],
        [char_to_bit(ch) for ch in row3],
    ]

    numeric_prefix_set = {tuple(p) for p in numeric_prefixes}

    plaintext_chars = []

    for start in range(0, ncols, 4):
        cell_bits = []
        for cell_idx in range(2):
            c0, c1 = start + 2*cell_idx, start + 2*cell_idx + 1
            rb = [
                [rows_bits[0][c0], rows_bits[0][c1]],
                [rows_bits[1][c0], rows_bits[1][c1]],
                [rows_bits[2][c0], rows_bits[2][c1]],
            ]
            cell_bits.append(rb)

        prefix_dots = bits_2x3_to_dots(cell_bits[0])
        payload_dots = bits_2x3_to_dots(cell_bits[1])

        is_digit = tuple(sorted(prefix_dots)) in numeric_prefix_set
        payload_key = tuple(sorted(payload_dots))
        if payload_key not in DOTS_TO_LETTER:
            raise ValueError(f"Unrecognized payload cell at cols {start+3}-{start+4}: dots={payload_dots}")
        letter = DOTS_TO_LETTER[payload_key]
        if is_digit:
            if letter not in LETTER_TO_DIGIT:
                raise ValueError(f"Payload pattern {payload_dots} does not map to a digit (a-j) under digit mode.")
            ch = LETTER_TO_DIGIT[letter]
        else:
            ch = letter
        plaintext_chars.append(ch)

    return ''.join(plaintext_chars)

def main():
    print("=== Braille Cipher Decoder ===")
    
    # Get key
    while True:
        key = input("Enter key (digits and letters): ").strip()
        if not key:
            print("Key cannot be empty, please try again")
            continue
        try:
            validate_key(key)
            break
        except ValueError as e:
            print(f"Key error: {e}")
            continue
    
    # Get cipher text three rows
    print("Enter the three rows of cipher text:")
    while True:
        row1 = input("Row 1: ").strip()
        row2 = input("Row 2: ").strip()
        row3 = input("Row 3: ").strip()
        
        if not (row1 and row2 and row3):
            print("All three rows cannot be empty, please try again")
            continue
            
        # Basic format check
        if not (len(row1) == len(row2) == len(row3)):
            print("All three rows must have the same length, please try again")
            continue
            
        if any(ch not in U for ch in row1+row2+row3):
            print("Cipher text can only contain digits and letters, please try again")
            continue
            
        break
    
    # Get numeric prefix
    while True:
        prefix_input = input("Enter the numeric prefix used during encoding (e.g. 3456,124): ").strip()
        try:
            prefixes = parse_prefixes(prefix_input)
            break
        except ValueError as e:
            print(f"Prefix format error: {e}")
            continue

    try:
        pt = decode(row1.lower(), row2.lower(), row3.lower(), key.lower(), prefixes)
        print(f"\n=== Decryption Result ===")
        print(pt)
    except ValueError as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
