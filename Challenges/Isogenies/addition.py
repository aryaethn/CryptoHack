p = 63079

x1 = 48622
x2 = 9460

y1 = 27709
y2 = 13819

up = (y1-y2)**2 % p
down = (x1-x2)**2 % p

frac = up * pow(down, -1, p) % p

print((frac - x1 - x2)%p)
