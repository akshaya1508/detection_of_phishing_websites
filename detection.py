from requests import get
from requests.exceptions import RequestException
from contextlib import closing
from bs4 import BeautifulSoup
import re
import numpy as np
import pandas as pd
import xlsxwriter
import requests
import json
import os


# Create a workbook and add a worksheet.


def simple_get(url):
    try:
        with closing(get(url, stream=True)) as resp:
            if is_good_response(resp):
                return resp.content
            else:
                return None

    except RequestException as e:
        log_error('Error during requests to {0} : {1}'.format(url, str(e)))
        return None


def is_good_response(resp):
    content_type = resp.headers['Content-Type'].lower()
    return (resp.status_code == 200
            and content_type is not None
            and content_type.find('html') > -1)


def log_error(e):
    print(e)


def compute_phishing(row, col, row_1, col_1):
    url = []
    u = []
    array = np.arange(1, 10)
    list = []
    for m in array:
        m = str(m)
        list.append(m)

    for x in list:
        raw_html_1 = simple_get(
            'https://www.phishtank.com/phish_search.php?page={}&valid=y&Search=Search'.format(x))
        html = BeautifulSoup(raw_html_1, 'html.parser')

        for td in html.select('td'):
            for name in td.text.split('\n'):
                if "http://" in name or "https://" in name:
                    url.append(name)
        for k in url:
            u.append(k.split("added")[0] or k.split("...")[0])

    worksheet.write(0, 0, 'URL')
    for z in u:
        worksheet.write(row, col,     z)
        row += 1
    worksheet.write(0, 10, 'Result')
    for z in u:
        worksheet.write(row_1, col_1,  -1)
        row_1 += 1

    return row, col, u, row_1


def compute_legitmate(raw_html_2, row, col, row_1, col_1):
    url = []
    html = BeautifulSoup(raw_html_2, 'html.parser')
    for td in html.select('td'):
        one_a_tag = td.findAll('a')
        for link in one_a_tag:
            if link.has_attr('href'):
                url.append(link.attrs['href'])
    for y in url:
        worksheet.write(row, col, y)
        row += 1

    for y in url:
        worksheet.write(row_1, col_1,     1)
        row_1 += 1
    return url


def validate_symbol(Final_URL, row, col):
    li_1 = []
    for y in Final_URL:
        if '@' in y:
            li_1.append(int('-1'))
        else:
            li_1.append(int('1'))
    worksheet.write(0, 1, 'Having @ symbol')
    for a in li_1:
        worksheet.write(row, col,     a)
        row += 1


def isIp(x):
    p = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    if p.search(x):
        return True
    else:
        return False


def validate_ip(Final_URL, row, col):
    li_2 = []
    for y in Final_URL:
        if isIp(y):
            li_2.append(int('-1'))
        else:
            li_2.append(int('1'))
    worksheet.write(0, 2, 'Presence of IP Address')
    for a in li_2:
        worksheet.write(row, col,     a)
        row += 1


def length(Final_URL, row, col):
    li_3 = []
    for y in Final_URL:
        if "https://" in y:
            if len(y.split("https://")[1].split("/")[0]) >= 20:
                li_3.append(-1)
            else:
                li_3.append(1)
        elif "http://" in y:
            if len(y.split("http://")[1].split("/")[0]) >= 20:
                li_3.append(-1)
            else:
                li_3.append(1)
    worksheet.write(0, 3, 'Length of URL')
    for a in li_3:
        worksheet.write(row, col,     a)
        row += 1


def slash(Final_URL, row, col):
    li_4 = []
    for y in Final_URL:
        if y.count('/') >= 4:
            li_4.append(int('-1'))
        else:
            li_4.append(int('1'))
    worksheet.write(0, 4, 'No. of Slashes')
    for a in li_4:
        worksheet.write(row, col,     a)
        row += 1


def special_char(Final_URL, row, col):
    li_5 = []
    s_check = re.compile('[@_!#$%^&*()<>?\|}{~]')
    for y in Final_URL:
        if(s_check.search(y) == None):
            li_5.append(int('1'))
        else:
            li_5.append(int('-1'))
    worksheet.write(0, 5, 'Special Character')
    for a in li_5:
        worksheet.write(row, col,     a)
        row += 1


def validate_dot(Final_URL, row, col):
    li_6 = []
    for y in Final_URL:
        if y.count(".") >= 3:
            li_6.append(int('-1'))
        else:
            li_6.append(int('1'))
    worksheet.write(0, 6, 'No.of Dots')
    for a in li_6:
        worksheet.write(row, col,     a)
        row += 1


def Hyphen(Final_URL, row, col):
    li_7 = []
    for y in Final_URL:
        if "https://" in y:
            if y.split("https://")[1].split("/")[0].count("-") > 1:
                li_7.append(-1)
            else:
                li_7.append(1)
        elif "http://" in y:
            if y.split("http://")[1].split("/")[0].count("-") > 1:
                li_7.append(-1)
            else:
                li_7.append(1)

    worksheet.write(0, 7, 'No. of Hyphen in Host Address')
    for a in li_7:
        worksheet.write(row, col,     a)
        row += 1


def email(Final_URL, row, col):
    li_8 = []
    for y in Final_URL:
        if 'email' in y:
            li_8.append(-1)
        else:
            li_8.append(1)

    worksheet.write(0, 8, '"Email" Keyword')
    for a in li_8:
        worksheet.write(row, col,     a)
        row += 1


def TLS(Final_URL, row, col):
    li_9 = []
    for y in Final_URL:
        try:
            print(y)
            # r = requests.get(y, verify=False, timeout=20)
            r = requests.get(y)
            if "https" in r.url:
                li_9.append(int('1'))
            else:
                li_9.append(int('-1'))
        except Exception as e:
            # except requests.exceptions.RequestException:
            li_9.append(int('-1'))

    worksheet.write(0, 9, 'TLS')
    for a in li_9:
        worksheet.write(row, col,     a)
        row += 1


def Age(Final_URL, row, col):
    li_10 = []
    str = " "
    for y in Final_URL:
        url = y.split("//")[-1].split("/")[0]
        if len(url.split(".")) == 2:
            url = url.split(".")[0]+".com"
        elif len(url.split(".")) >= 3:
            url = url.split(".")[0]+".com"

        show = "https://input.payapi.io/v1/api/fraud/domain/age/" + url
        r = requests.get(show)
        try:
            if r.status_code == 200:
                data = r.text
                jsonToPython = json.loads(data)
                str = jsonToPython['message']
                num = str.split(" ")[3]
                if int(num) <= 365:
                    li_10.append(-1)
                else:
                    li_10.append(1)
            else:
                li_10.append(-1)
        except Exception as e:
            li_10.append(-1)
        print(y)
    worksheet.write(0, 10, 'Age of URL')
    for a in li_10:
        worksheet.write(row, col,     a)
        row += 1


if __name__ == "__main__":
    name = input("Do you want to name the excel file press (y/n)\n")
    if name == 'y':
        workbook = xlsxwriter.Workbook(
            input('Type the name of the excel you want\n')+".xlsx")
    else:
        workbook = xlsxwriter.Workbook('test1.xlsx')

    worksheet = workbook.add_worksheet()

    row, col, u, row_1 = compute_phishing(1, 0, 1, 11)
    raw_html_2 = simple_get('https://moz.com/top500')
    url = compute_legitmate(raw_html_2, row, col, row_1, 11)

    Final_URL = " "

    Final_URL = u+url
    validate_symbol(Final_URL, 1, 1)
    validate_ip(Final_URL, 1, 2)
    length(Final_URL, 1, 3)
    slash(Final_URL, 1, 4)
    special_char(Final_URL, 1, 5)
    validate_dot(Final_URL, 1, 6)
    Hyphen(Final_URL, 1, 7)
    email(Final_URL, 1, 8)
    TLS(Final_URL, 1, 9)
    Age(Final_URL, 1, 10)
    print("Your workbook is ready to be used!")
    workbook.close()
