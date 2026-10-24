from PIL import Image, ImageDraw, ImageFont
import os, sys
out = sys.argv[1]
S = 512
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

def shield(d, box, fill, outline, width):
    x0,y0,x1,y1 = box
    w = x1-x0; h = y1-y0
    pts = [(x0, y0+h*0.12), (x0+w*0.5, y0), (x1, y0+h*0.12), (x1, y0+h*0.50),
           (x0+w*0.5, y1), (x0, y0+h*0.50)]
    # smoother: polygon with curve approximation for bottom
    import math
    poly = [(x0, y0+h*0.13), (x0+w*0.5, y0), (x1, y0+h*0.13)]
    for i in range(0, 21):
        t = i/20
        # right side curve down to tip
        x = x1 - (w*0.5)*(t**1.6)
        y = y0+h*0.13 + (h*0.87)*t
        poly.append((x, y))
    for i in range(20, -1, -1):
        t = i/20
        x = x0 + (w*0.5)*(t**1.6)
        y = y0+h*0.13 + (h*0.87)*t
        poly.append((x, y))
    d.polygon(poly, fill=fill)
    if width: d.line(poly + [poly[0]], fill=outline, width=width, joint="curve")

def logo(size_box, img, color=(22, 92, 190), dark=(10, 45, 110), text="FF"):
    d = ImageDraw.Draw(img)
    x0,y0,x1,y1 = size_box
    shield(d, size_box, dark, None, 0)
    m = (x1-x0)*0.06
    shield(d, (x0+m, y0+m, x1-m, y1-m*1.4), color, None, 0)
    # text
    h = y1-y0
    f = ImageFont.truetype(FONT, int(h*0.46))
    bb = d.textbbox((0,0), text, font=f)
    tw, th = bb[2]-bb[0], bb[3]-bb[1]
    cx = (x0+x1)/2; cy = y0 + h*0.44
    d.text((cx - tw/2 - bb[0], cy - th/2 - bb[1]), text, font=f, fill=(255,255,255))

def arrow(d, cx, top, bottom, width, up, color):
    # vertical arrow
    head = width*1.9
    hh = width*1.6
    if up:
        d.rectangle((cx-width/2, top+hh*0.9, cx+width/2, bottom), fill=color)
        d.polygon([(cx-head/2*1.0- width*0.2, top+hh), (cx, top), (cx+head/2*1.0+width*0.2, top+hh)], fill=color)
    else:
        d.rectangle((cx-width/2, top, cx+width/2, bottom-hh*0.9), fill=color)
        d.polygon([(cx-head/2- width*0.2, bottom-hh), (cx, bottom), (cx+head/2+width*0.2, bottom-hh)], fill=color)

def app_icon():
    img = Image.new("RGBA", (S,S), (0,0,0,0))
    logo((S*0.08, S*0.04, S*0.92, S*0.96), img)
    return img

def arc_arrow(d, cx, cy, r, width, start, end, color):
    """Flecha gorda en semicírculo: arco de 'start' a 'end' (grados, sentido de PIL) con la punta en 'end'."""
    import math
    step = -1 if end < start else 1
    head_len = width * 1.6
    head_ang = math.degrees(head_len / r)
    arc_end = end - step * head_ang * 0.55
    a0, a1 = (arc_end, start) if step < 0 else (start, arc_end)
    d.arc((cx - r - width/2, cy - r - width/2, cx + r + width/2, cy + r + width/2), a0, a1, fill=color, width=int(width))
    # redondear el principio del arco
    t0 = math.radians(start)
    sx, sy = cx + r*math.cos(t0), cy + r*math.sin(t0)
    d.ellipse((sx - width/2, sy - width/2, sx + width/2, sy + width/2), fill=color)
    # punta: triángulo tangente al círculo
    tb = math.radians(arc_end)
    bx, by = cx + r*math.cos(tb), cy + r*math.sin(tb)
    tt = math.radians(arc_end + step * head_ang)
    tx, ty = cx + r*math.cos(tt), cy + r*math.sin(tt)
    ox, oy = math.cos(tb), math.sin(tb)     # hacia fuera
    half = width * 1.3
    d.polygon([(bx + ox*half, by + oy*half), (tx, ty), (bx - ox*half, by - oy*half)], fill=color)

def tray(inc, outg, blockall):
    img = Image.new("RGBA", (S,S), (0,0,0,0))
    d = ImageDraw.Draw(img)
    green_on, red_on, off = (30, 220, 30), (240, 35, 35), (150, 150, 150)
    w = S*0.15
    c = S/2
    r = S/2 - w/2 - S*0.01
    # izquierda: verde hacia abajo (entran datos); derecha: roja hacia arriba (salen datos)
    arc_arrow(d, c, c, r, w, 245, 118, green_on if inc else off)
    arc_arrow(d, c, c, r, w, 65, -62, red_on if outg else off)
    box = (S*0.25, S*0.17, S*0.75, S*0.86)
    if blockall:
        logo(box, img, color=(200, 30, 30), dark=(110, 10, 10))
    else:
        logo(box, img)
    return img

sizes = [(16,16),(20,20),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)]
app = app_icon()
app.save(os.path.join(out, "FirewallFamiliar.ico"), sizes=sizes)
app.resize((256,256), Image.LANCZOS).save(os.path.join(out, "logo.png"))
tray_sizes = [(16,16),(20,20),(24,24),(32,32),(48,48)]
for blk in (False, True):
    for name, i, o in (("nada",0,0),("entra",1,0),("sale",0,1),("ambos",1,1)):
        t = tray(i, o, blk)
        t.save(os.path.join(out, f"tray-{'bloq-' if blk else ''}{name}.ico"), sizes=tray_sizes)
# preview sheet
sheet = Image.new("RGBA", (900, 300), (240,240,240,255))
sheet.paste(app.resize((256,256), Image.LANCZOS), (10, 20), app.resize((256,256), Image.LANCZOS))
x = 300
for blk in (False, True):
    for name, i, o in (("nada",0,0),("entra",1,0),("sale",0,1),("ambos",1,1)):
        t = tray(i,o,blk)
        for k, sz in enumerate((64, 32, 16)):
            im = t.resize((sz,sz), Image.LANCZOS)
            sheet.paste(im, (x, 20 + (0 if not blk else 140) + [0,70,108][k]), im)
        x += 75
    x = 300
sheet.save(os.path.join(out, "..", "preview.png"))
