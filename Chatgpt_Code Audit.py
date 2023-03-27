import os
import openai
import fnmatch
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# 用你的 OpenAI API 密钥替换这里
openai.api_key = "your_openai_api_key_here"

print("""
 .----------------.  .----------------.  .-----------------. .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |   ______     | || |      __      | || | ____  _____  | || |  ________    | || |      __      | || |     ____     | |
| |  |_   __ \   | || |     /  \     | || ||_   \|_   _| | || | |_   ___ `.  | || |     /  \     | || |   .' __ '.   | |
| |    | |__) |  | || |    / /\ \    | || |  |   \ | |   | || |   | |   `. \ | || |    / /\ \    | || |   | (__) |   | |
| |    |  ___/   | || |   / ____ \   | || |  | |\ \| |   | || |   | |    | | | || |   / ____ \   | || |   .`____'.   | |
| |   _| |_      | || | _/ /    \ \_ | || | _| |_\   |_  | || |  _| |___.' / | || | _/ /    \ \_ | || |  | (____) |  | |
| |  |_____|     | || ||____|  |____|| || ||_____|\____| | || | |________.'  | || ||____|  |____|| || |  `.______.'  | |
| |              | || |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------' 
 Github:https://github.com/pandasec888
 """)



def audit_code(code: str, language: str) -> str:
    time.sleep(1)  # 等待1秒
    response = openai.Completion.create(
        engine="text-davinci-002",
        prompt=f"Perform a detailed security audit for the following {language} code snippet, including the line numbers with potential vulnerabilities, the specific code, and suggestions for fixing the issues:\n\n{code}\n",
        temperature=0.5,
        max_tokens=300,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    return response.choices[0].text.strip()

def translate_to_chinese(text: str) -> str:
    time.sleep(1)  # 等待1秒
    response = openai.Completion.create(
        engine="text-davinci-002",
        prompt=f"Translate the following English text to Chinese:\n\n{text}\n",
        temperature=0.5,
        max_tokens=100,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    return response.choices[0].text.strip()

def audit_file(file_path: str, language: str):
    with open(file_path, 'r', encoding='utf-8') as file:
        code = file.read()
    audit_result = audit_code(code, language)
    return (file_path, audit_result)

def audit_directory(path: str):
    supported_files = []

    for root, dirnames, filenames in os.walk(path):
        for extension in ('*.java', '*.php', '*.jsp', '*.jspx', '*.asp', '*.aspx'):
            for filename in fnmatch.filter(filenames, extension):
                supported_files.append(os.path.join(root, filename))

    audit_results = {}
    files_to_audit = supported_files

    with ThreadPoolExecutor() as executor:
        for file_path, audit_result in tqdm(executor.map(audit_file, files_to_audit, [file_path.split(".")[-1].upper() for file_path in files_to_audit]), total=len(files_to_audit)):
            audit_results[file_path] = audit_result

    return audit_results

def write_results_to_file(results: dict):
    with open("result.md", "w", encoding="utf-8") as file:
        for file_path, result in results.items():            
            # 分割结果，按漏洞总结和详细信息组织
            result_parts = result.split('\n', 1)
            if len(result_parts) == 2:
                vulnerabilities_summary, vulnerabilities_details = result_parts
            else:
                vulnerabilities_summary = result
                vulnerabilities_details = "未提供详细信息"

            print(f"审计结果 - {file_path}:")
            print(f"{vulnerabilities_summary}")
            print(f"{vulnerabilities_details}\n")

            file.write(f'## {file_path}\n\n')
            file.write(f'**漏洞总结**\n\n```\n{vulnerabilities_summary}\n```\n\n')
            file.write(f'**漏洞详细信息**\n\n```\n{vulnerabilities_details}\n```\n\n---\n\n')

if __name__ == "__main__":
    directory_path = input("Enter the directory path: ")
    results = audit_directory(directory_path)
    write_results_to_file(results)
    print("审计结果已写入 result.md 文件.")
