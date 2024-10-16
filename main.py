import re
import requests
from PIL import Image
from super_image import EdsrModel, ImageLoader
import time 
import uuid
import threading
import json
import queue

model = EdsrModel.from_pretrained('eugenesiow/edsr-base', scale=2)

with open('cookies.txt', 'r') as f:
    cookies = f.readlines()

cookie_number = 0

def GetXSRFToken(token):
    response = requests.post('https://auth.roblox.com/v1/logout', cookies={'.ROBLOSECURITY': token})
    return response.headers.get('x-csrf-token')


def GetAuthenticationData(Cookie):
    data = requests.get("https://users.roblox.com/v1/users/authenticated",
        cookies = {'.ROBLOSECURITY': Cookie},
        headers = {'x-csrf-token': GetXSRFToken(Cookie), "referer": "https://www.roblox.com"}
    ).json()

    return data

def CheckCookie(cookie):
    data = GetAuthenticationData(cookie)
    return data != {'errors': [{'code': 0, 'message': 'Unauthorized'}]}, data.get("id") 

def get_valid_cookie():
    global cookie_number
    while True:
        cookie = cookies[cookie_number].strip()
        valid, user_id = CheckCookie(cookie)
        if valid:
            print("\033[92m" + "Valid cookie found" + "\033[0m")
            return cookie, user_id
        else:
            cookie_number = (cookie_number + 1) % len(cookies)
            print("\033[91m" + "Cookie is invalid, trying another one..." + "\033[0m")

def download_image(threadname, asset_id):
    response = requests.get(f"https://assetdelivery.roblox.com/v1/asset/?ID={asset_id}")
    with open(f"{threadname}.png", "wb") as file:
        file.write(response.content)
    print("\033[94m" + "Image downloaded successfully" + "\033[0m")

def begin_asset_upload(data, name, headers, cookies, userid):
    files = {
        "fileContent": (f"upscaled.png", data, "image/png"),
        "request": (None, json.dumps({
            "displayName":"tokyo",
            "description":"Decal",
            "assetType":"Decal",
            "creationContext":{
                "creator":{
                    "userId": userid
                },
                "expectedPrice":0
            }
        }))
    }

    response = requests.post("https://apis.roblox.com/assets/user-auth/v1/assets", headers=headers, files=files, cookies=cookies)
    if response.status_code != 200:
        print(response.text)

    response_data = response.json()
    operation_id = response_data.get("operationId")
    if not operation_id:
        print("\033[93m" + "Failed to initiate asset upload, retrying..." + "\033[0m")
        return begin_asset_upload(data, name, headers, cookies, userid)
    print("\033[96m" + "Asset upload initiated" + "\033[0m")
    return operation_id

def poll_for_upload(operation_id, headers, cookies):
    print("\033[93m" + "Checking asset status..." + "\033[0m")
    status_response = requests.get(f"https://apis.roblox.com/assets/user-auth/v1/operations/{operation_id}", headers=headers, cookies=cookies)
    status_data = status_response.json()

    if status_data.get("done"):
        moderation_result = status_data.get("response", {}).get("moderationResult", {})
        if moderation_result.get("moderationState") == "Approved":
            asset_id = status_data["response"].get("assetId")
            print("\033[92m" + "Asset upload successful" + "\033[0m")
            return asset_id


def upscale_asset(threadname, asset_id, cookie, csrf, userid):
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "x-csrf-token": csrf,
    }

    cookies = {".ROBLOSECURITY": cookie}
    
    try: 
        download_image(threadname, asset_id)
        image = Image.open(f"{threadname}.png")
    except:
        print("Data corrupted, skipping")
        return asset_id


    preds = model(ImageLoader.load_image(image))
    ImageLoader.save_image(preds, f'upscaled_2x{threadname}.png')
    print("\033[96m" + "Image upscaled successfully" + "\033[0m")

    with open(f"upscaled_2x{threadname}.png", "rb") as file:
        data = file.read()

    operation_id = begin_asset_upload(data, "japan", headers, cookies, userid)

    while True:
        asset_id = poll_for_upload(operation_id, headers, cookies)
        if asset_id:
            break 
        time.sleep(1)
        print("\033[93m" + "polling for image" + "\033[0m")

    response = requests.get(f"https://assetdelivery.roblox.com/v1/asset/?id={asset_id}")
    image_id = re.search(r'<url>(.*?)</url>',  response.text).group(1)
    return image_id



def main(input_file, output_file):
    with open(input_file, "r") as file:
        input_string = file.read()

    pattern = r'<Content name="TextureID"><url>rbxassetid://(\d+)</url></Content>'
    matches = re.findall(pattern, input_string)
    length = len(matches)
    upscaled = { }

    queue1 = queue.Queue()
    queue1.queue = queue.deque(matches)
    
    def threadbody(a):
        global length
        cookie, userid = get_valid_cookie()
        csrf = GetXSRFToken(cookie)
        threadname = str(uuid.uuid4())

        for _ in range(a):
            current = queue1.get()
            if upscaled.get(current): continue

            upscaled[current] = upscale_asset(threadname, current, cookie, csrf, userid)

    Amount = 140
    c = length / Amount 
    r = c % 1
    a = int(c - r)

    print("\033[92m" + f"Starting {a + 1} threads for processing" + "\033[0m")

    try:
        threads = []
        for i in range(a):
            t = threading.Thread(target=threadbody, args=(Amount,))
            threads.append(t)
            t.start()
            
        if r != 0:   
            t = threading.Thread(target=threadbody, args=(int(Amount * r),))
            t.start()
        
        for t in threads:
            t.join()

        if r != 0:
            t.join()
    except: 
        print("\033[91m" + "Processing stopped early due to an error" + "\033[0m")
        
    output_string = input_string

    for old_asset in upscaled.keys():
        output_string = output_string.replace(old_asset, upscaled[old_asset])

    with open(output_file, "w") as file:
        file.write(output_string)

    print("\033[94m" + f"Processing completed. Output saved to {output_file}" + "\033[0m")

if __name__ == "__main__":
    input_file = "" #"japan.rbxmx"
    output_file = ""#"upscaled_japan.rbxmx"
    main(input_file, output_file)
