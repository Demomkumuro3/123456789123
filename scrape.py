import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

def scrape_proxies():
    proxy_sources = [
        "https://www.proxy-list.download/api/v1/get?type=socks4",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxies.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
        "https://proxyspace.pro/socks5.txt",
        "https://proxyspace.pro/http.txt",
        "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
        "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
        "https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys/main/cnfree.txt",
        "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/all.txt",
        "https://raw.githubusercontent.com/yuceltoluyag/Free-Proxy-List/main/proxies/proxy-list.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
        "https://github.com/TheSpeedX/PROXY-List/raw/master/http.txt",
        "https://geonode.com/free-proxy-list",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxies.txt",
        "https://github.com/jetkai/proxy-list/raw/main/online-proxies/txt/proxies-http.txt",
        "https://free-proxy-list.net/",
        "https://github.com/oxylabs/free-proxy-list/raw/main/proxy.txt",
        "https://spys.me/proxy.txt",
        "https://proxyelite.info/files/proxy/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/txt/proxies-socks4.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies_anonymous.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/socks4.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks4.txt",
        "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
        "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/https.txt",
        "https://raw.githubusercontent.com/malbink/Free-Proxy-List/master/proxies.txt",
        "https://raw.githubusercontent.com/aniyun009/free-proxy-list/main/proxy-list.txt",
        "https://raw.githubusercontent.com/andybalholm/aaa-proxy-list/main/list.txt",
        "https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/https.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/proxies.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt",
        "https://raw.githubusercontent.com/hanwaytech/free-proxy-list/main/proxy-list.txt",
        "https://raw.githubusercontent.com/Bardiafa/Proxy-Leecher/main/output.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/https.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list_anonymous.txt",
        "https://raw.githubusercontent.com/Jiejiejiayou/IPTVProxy/main/proxy/http.txt",
        "https://raw.githubusercontent.com/Jiejiejiayou/IPTVProxy/main/proxy/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/https.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies_anonymous.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/anonymous.txt",
        "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies_anonymous/http.txt",
        "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies_anonymous/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-anonymous.txt",
    ]
    proxies = set()

    def fetch(url):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and ":" in line:
                        proxies.add(line)
                print(f"{Fore.GREEN}[+] Scraped from {url}")
            else:
                print(f"{Fore.RED}[-] Failed ({response.status_code}) from {url}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error scraping {url} | {e}")

    print(f"{Fore.YELLOW}[!] Scraping fresh proxies from {len(proxy_sources)} sources...\n")

    with ThreadPoolExecutor(max_workers=30) as executor:
        executor.map(fetch, proxy_sources)

    print(f"\n{Fore.CYAN}[✓] Scraping completed. Total unique proxies: {len(proxies)}")

    with open("proxies.txt", "w") as file:
        for proxy in sorted(proxies):
            file.write(proxy + "\n")

    print(f"{Fore.CYAN}[✓] Saved to proxies.txt\n")

if __name__ == "__main__":
    scrape_proxies()
