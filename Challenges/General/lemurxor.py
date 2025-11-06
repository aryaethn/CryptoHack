from PIL import Image, ImageChops
im1 = Image.open('lemur.png')
im2 = Image.open('flag.png')
 
pix1 = im1.load()
pix2 = im2.load()
 
#Both images have the same width & height
w, h = im1.size
 
imn = Image.new("RGB", (w, h), "black")
pixn = imn.load()
 
for i in range(w):    
    for j in range(h): 
    
        r1, g1, b1 = pix1[i, j] 
        r2, g2, b2 = pix2[i, j] 
        
        rn = r1^r2
        gn = g1^g2
        bn = b1^b2
 
        
        pixn[i,j] =  (rn, gn, bn)
        
#imn.show()
imn.save("new.png")