import pefile, peutils, hashlib

class Malware():

    def __init__(self, file):
        try:
            self.hashes = {}
            
            with open(file, 'rb') as f:
                data = f.read()
                
            self.hashes['md5'] = hashlib.md5(data).hexdigest()
            self.hashes['sha1'] = hashlib.sha1(data).hexdigest()
            self.hashes['sha256'] = hashlib.sha256(data).hexdigest()
            self.hashes['sha512'] = hashlib.sha512(data).hexdigest()
            
            self.file = pefile.PE(file)
        except pefile.PEFormatError:
            print("[!] File is not a valid PE file")
            exit()

    def check_arch(self):
        if hex(self.file.FILE_HEADER.Machine) == '0x14c':
            print("Binary is x86")
            self.arch = 'x86'
        else:
            print("Binary is x64")
            self.arch = 'x64'

    def get_sections(self):
        self.sections = []
        for section in self.file.sections:
            key = {}
            key["name"] = section.Name.decode().rstrip('\x00')
            key["entropy"] = section.get_entropy()
            self.sections.append(key)

    def get_imports(self):
        self.imports = []
        for entry in self.file.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                self.imports.append(imp.name.decode())
    
    def check_if_packed(self):
        self.signatures = peutils.SignatureDatabase('assets/packer_sig.txt')
        self.packer = self.signatures.match(self.file, ep_only=True)
        
        if self.packer is not None:
            print("[!] File is packed with: " + self.packer[0])
            self.is_packed = True
        else:
            print("[!] Checking if packed manually ...")
            if self.sections[0]['name'] == '.text' and self.sections[0]['entropy'] > 6:
                print("[!] File is probably packed")
                print(f"The section {self.sections[0]['name']} has {self.sections[0]['entropy']} entropy")
                self.is_packed = False

mal = Malware("trick.exe")
mal.get_sections()
mal.get_imports()
mal.check_if_packed()





