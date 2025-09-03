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

def rand_from(s: str) -> str:
    return secrets.choice(s)

def encode(plaintext: str, key: str, numeric_prefixes: list[tuple[int, ...]]):
    K = validate_key(key)
    Z = ''.join(ch for ch in U if ch not in K)
    plaintext = plaintext.lower()
    if any(ch not in U for ch in plaintext):
        raise ValueError("Plaintext must contain only digits 0-9 and lowercase letters a-z.")

    numeric_prefix_set = {tuple(p) for p in numeric_prefixes}

    rows = [[], [], []]

    for ch in plaintext:
        is_digit = ch in string.digits

        if is_digit:
            prefix_dots = secrets.choice(list(numeric_prefix_set))
        else:
            while True:
                mask = secrets.randbits(6)
                dots = tuple(sorted(i+1 for i in range(6) if (mask >> i) & 1))
                if dots not in numeric_prefix_set:
                    prefix_dots = dots
                    break

        payload_letter = DIGIT_TO_LETTER[ch] if is_digit else ch
        payload_dots = LETTER_TO_DOTS[payload_letter]

        for cell_dots in (prefix_dots, payload_dots):
            rb = dots_to_bits_2x3(cell_dots)
            for r in range(3):
                rows[r].extend(rb[r])

    out_rows = []
    for r in range(3):
        chars = [rand_from(K) if b==1 else rand_from(Z) for b in rows[r]]
        out_rows.append(''.join(chars))

    dbg = {
        "K": K,
        "Z_len": len(Z),
        "cipher_cols": len(rows[0]),
        "plaintext_len": len(plaintext),
        "numeric_prefixes": [list(p) for p in numeric_prefixes],
    }
    return out_rows[0], out_rows[1], out_rows[2], dbg

def main():
    print("=== Braille 密码编码器 ===")
    
    # 获取密钥
    while True:
        key = input("请输入密钥 (数字和字母): ").strip()
        if not key:
            print("密钥不能为空，请重新输入")
            continue
        try:
            validate_key(key)
            break
        except ValueError as e:
            print(f"密钥错误: {e}")
            continue
    
    # 获取明文
    while True:
        plaintext = input("请输入要加密的文本 (数字和字母): ").strip()
        if not plaintext:
            print("文本不能为空，请重新输入")
            continue
        plaintext = plaintext.lower()
        if any(ch not in U for ch in plaintext):
            print("文本只能包含数字和字母，请重新输入")
            continue
        break
    
    # 询问是否使用默认数字前缀
    use_default = input("使用默认数字前缀? (y/n，默认y): ").strip().lower()
    if use_default in ['', 'y', 'yes']:
        prefixes = DEFAULT_NUMERIC_PREFIXES
    else:
        while True:
            prefix_input = input("请输入数字前缀 (如 3456,124): ").strip()
            try:
                prefixes = parse_prefixes(prefix_input)
                break
            except ValueError as e:
                print(f"前缀格式错误: {e}")
                continue

    try:
        r1, r2, r3, dbg = encode(plaintext, key.lower(), prefixes)
        print("\n=== 加密结果 ===")
        print(r1)
        print(r2)
        print(r3)
            
    except ValueError as e:
        print(f"加密失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
