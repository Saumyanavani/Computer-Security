import hashlib

if __name__ == '__main__':
    h = hashlib.new('sha512')
    h.update(b"My name is Saumya")
    print(h.hexdigest())
