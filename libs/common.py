#ascii art code from www.hackerearth.com/notes/beautiful-python-a-simple-ascii-art-generator-from-images/

from PIL import Image

ASCII_CHARS = [ '#', '?', '%', '.', 'S', '+', '.', '*', ':', ',', '@','-','_','X']

def scale_image(image, new_width=100):
    """Resizes an image preserving the aspect ratio.
    """
    (original_width, original_height) = image.size
    aspect_ratio = original_height/float(original_width)
    new_height = int(aspect_ratio * new_width)

    new_image = image.resize((new_width, new_height))
    return new_image

def convert_to_grayscale(image):
    return image.convert('L')

def map_pixels_to_ascii_chars(image, range_width=25):
    """Maps each pixel to an ascii char based on the range
    in which it lies.

    0-255 is divided into 11 ranges of 25 pixels each.
    """

    pixels_in_image = list(image.getdata())
    pixels_to_chars = [ASCII_CHARS[pixel_value/range_width] for pixel_value in
            pixels_in_image]

    return "".join(pixels_to_chars)

def convert_image_to_ascii(image, new_width=100):
    image = scale_image(image)
    image = convert_to_grayscale(image)

    pixels_to_chars = map_pixels_to_ascii_chars(image)
    len_pixels_to_chars = len(pixels_to_chars)

    image_ascii = [pixels_to_chars[index: index + new_width] for index in
            xrange(0, len_pixels_to_chars, new_width)]

    return "\n".join(image_ascii)

def handle_image_conversion(image_filepath, new_width=100):
    image = None
    try:
        image = Image.open(image_filepath)
    except Exception, e:
        print "Unable to open image file {image_filepath}.".format(image_filepath=image_filepath)
        print e
        return

    return convert_image_to_ascii(image, new_width)
    
def module_exists(module_name):
    try:
        __import__(module_name)
    except ImportError:
        return False
    else:
        return True

#Similar to nix which program
def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

#Very specific to linux
def isForwardingEnabled(self):
    flag = ''
    forwarding_filename =  '/proc/sys/net/ipv4/ip_forward'
    with open(forwarding_filename, 'r') as forwarding_file:
        flag = forwarding_file.readline()
    if self.debug is not None:
        print 'Forwarding flag ' + forwarding_filename + ' ' +flag
    flag = flag.rstrip()
    if flag == '1':
        return True
