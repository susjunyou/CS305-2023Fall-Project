class HttpRequest:

    def __init__(self):
        self.is_file = False
        self.file_size = 0
        self.file_name = ''
        self.file_path = ''
        self.file_type = ''
        self.file_encoding = ''
        self.username = ''
        self.password = ''
        self.is_chunked = False
        self.is_login = False
        self.is_encrypt = False
        self.public_key = ''
        self.private_key = ''
        self.aes_key = None
        self.is_large_file = False
