# Teaching Plan: Intro to Assembly with Stack Visualizer

This document provides a ready-to-use classroom flow with concrete examples.
It focuses on stack behavior, function calls, and memory layout.

---

## Audience and goals
Beginner students learning x86 assembly concepts and stack frames.

By the end, students should understand:
- prologue/epilogue (EBP/ESP)
- local variables and offsets
- call/ret behavior
- conditional jumps
- basic buffer overflow effects

---

## Setup (once per lab)
```bash
python3 -m venv backends/.venv
source backends/.venv/bin/activate
pip install -r requirements.txt
pip install unicorn
```

Open VS Code and use:
- `Stack Visualizer: Run Trace...`

Recommended toggles:
- Capture only in binary = ON
- Start symbol = main

---

## Lesson flow (60-90 minutes)

### Part 1: Stack frame basics (10-15 min)
Goal: recognize prologue/epilogue and stack growth.

Code (example1.c):
```c
int add(int a, int b) {
  int sum = a + b;
  return sum;
}
```

What to show:
- `push ebp` / `mov ebp, esp`
- `sub esp, X`
- `mov eax, [ebp+8]` (arguments)
- `leave` / `ret`

Key idea:
`EBP` is a fixed reference, `ESP` moves.

---

### Part 2: Local variables and offsets (10-15 min)
Goal: see local variables at RBP- offsets.

Code (example2.c):
```c
int demo() {
  int x = 5;
  int y = 8;
  return x + y;
}
```

What to show:
- `x` and `y` stored at `[ebp-0x..]`
- changes in the stack panel

Key idea:
locals are laid out by compiler, not necessarily in source order.

---

### Part 3: Call and return mechanics (10 min)
Goal: visualize call/ret and return address.

Code (example3.c):
```c
void hello() { }
int main() {
  hello();
  return 0;
}
```

What to show:
- `call hello` pushes return address
- stack shows an extra word
- `ret` pops the address

---

### Part 4: Conditional jumps (10 min)
Goal: read `cmp` + jump instructions.

Code (example4.c):
```c
int main() {
  int i = 0;
  while (i < 3) {
    i++;
  }
  return i;
}
```

What to show:
- `cmp` and `jl`/`jg`
- register values changing each step

---

### Part 5: Buffer overflow demo (15-20 min)
Goal: show how input overwrites adjacent data.

Code (example5.c):
```c
void win() { }
int main() {
  char buffer[32];
  int secret = 0;
  read(0, buffer, 64);
  if (secret == 0x42424242) win();
}
```

Input example:
```
A*32 + BBBB
```

What to show:
- buffer region in the stack panel
- `secret` changed to 0x42424242 (BBBB)
- control flow entering `win`

Key idea:
overflow writes beyond the intended buffer.

---

## Classroom tips
- Pause at the prologue to explain EBP/ESP.
- Ask students to predict the next instruction.
- Use the disasm highlight to connect source and machine code.
- Keep `max-steps` small (200-800) for live demos.

---

## Notes and limitations
- Using `sys_read` is the most stable for 32-bit demos.
- `printf/malloc` require libc; static builds are more reliable.
- If `output.json` is empty, raise `--max-steps` and confirm `start-symbol`.

---

## Optional exercise ideas
- Change buffer size and observe the layout difference.
- Add a new local variable and predict its offset.
- Replace `while` with `if` and compare jumps.
