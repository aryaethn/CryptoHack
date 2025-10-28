import re

# Read the output file
with open('output_479698cde19aaa05d9e9dfca460f5443.txt', 'r') as f:
    content = f.read()

# Extract p (the first number)
p = 0
p_match = re.search(r'p = (\d+)', content)
if p_match:
    p = int(p_match.group(1))
    
ints = []
# Extract ints (the list of numbers)
ints_match = re.search(r'ints = \[(.+)\]', content, re.DOTALL)
if ints_match:
    ints_str = ints_match.group(1)
    # Split by comma and strip whitespace/newlines
    ints = [int(x.strip()) for x in ints_str.split(',')]

def legendre_symbol(a, p):
    return pow(a, (p - 1) // 2, p)

for i in ints:
    res = legendre_symbol(i, p)
    if res == 1:
        print(pow(i, (p + 1) // 4, p))
