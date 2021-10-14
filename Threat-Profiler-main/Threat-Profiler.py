from numpy.lib.function_base import kaiser
from pandas import read_excel
import pandas as pd
import json,os 
from simple_term_menu import TerminalMenu
from jinja2 import Environment, FileSystemLoader

#Banner

banner = """  
 Intellisec Solutions Threat Profiler v 0.1  

[    377 Threat Actors - 122 Mapped APTs       ]
[    10 Mapped Threat Intelligence Reports     ]
[    1563 Tools   8988 Threat Report           ]
[    Usage: python3 Threat-profiler.py         ]

"""
print(banner)


# Initial Variables and lists

ActCnt = []
ActIndus = []
Tools = []
ExtIndus = []
ExtCnt = []

# Report Generation Configuration

file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)
template = env.get_template('hi.html')


# Get the list of Sectors from user
input_string = input("Enter Sectors: ")
Indus  = input_string.split(",")
for sector in Indus:
    print("[+] You selected the following Sectors: ",str(sector))
    
# Get the list of Countries from user

input_string2 = input("Enter The Countries: ")
Countries  = input_string2.split(",")
for country in Countries:
    print("[+] You selected the following Countries: ",str(country))


#Indus = ["Energy"]
#Countries = ["Japan"]


print("[+] Do you want to use a Threat Intelligence Mapped Report? ")
terminal_menu = TerminalMenu(
        ["Cisco-talos Quarterly Report-incident-response-trends-in-summer-2020-(ransomware)", 
         "Cisco-talos-(quarterly-report---incident-response-trends-from-fall-2020)", 
         "Cisco-talos-(quarterly-report---incident-response-trends-from-spring-2021)",
         "Cisco-talos-(quarterly-report---incident-response-trends-from-winter-2020-21)",
         "Fireeye-mandiant---m-trends-2021",
         "Mcafee-(labs-threats-report---april-2021-(top-5-per-tactic))",
         "Rapid7-(2020-q2-threat-report---cumulative-by-industry)",
         "Sophos-(top-5-techniques-observed-with-each-tactic-in-20202021)",
         "Windows-linux-macos_pwc---cyber-threats-2020-a-year-in-retrospect",
         "Windows-linux-macos_redcanary---2021-threat-detection-report",
         "NO Thanks"],
        multi_select=True,
        show_multi_select_hint=True,
    )
menu_entry_indices = terminal_menu.show()
#print(menu_entry_indices)
#print(menu_entry_indices[0])
#print(terminal_menu.chosen_menu_entries)
"""
for sl in menu_entry_indices:
    if sl == 0:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_cisco-talos-(quarterly-report---incident-response-trends-from-fall-2020).json' -P Navigation-Layers -q"
        os.system(Command) # Download ATT&CK Navigation Layers
    elif sl == 1:
        Command = "wget 'https://github.com/chihebchebbi/ThreatReports/blob/main/attack_all_cisco-talos-(quarterly-report---incident-response-trends-from-spring-2021).json' -P Navigation-Layers -q"
        os.system(Command) # Download ATT&CK Navigation Layers
    elif sl == 2:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_cisco-talos-(quarterly-report---incident-response-trends-from-winter-2020-21).json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 3:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_cisco-talos---quarterly-report-incident-response-trends-in-summer-2020-(ransomware).json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 4:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_fireeye-mandiant---m-trends-2021.json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 5:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_mcafee-(labs-threats-report---april-2021-(top-5-per-tactic)).json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 6:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_rapid7-(2020-q2-threat-report---cumulative-by-industry).json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 7:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_all_sophos-(top-5-techniques-observed-with-each-tactic-in-20202021).json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 8:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_windows-linux-macos_pwc---cyber-threats-2020-a-year-in-retrospect.json' -P Navigation-Layers -q"
        os.system(Command)
    elif sl == 9:
        Command = "wget 'https://raw.githubusercontent.com/chihebchebbi/ThreatReports/main/attack_windows-linux-macos_redcanary---2021-threat-detection-report.json' -P Navigation-Layers -q"
        os.system(Command)
"""

print("[+] Mapped Threat Intelligence Reports were Generated Successfully!") 
# Load Group Details
file_name = "APT-groups3.xlsx"
my_sheet = "groups"
df = read_excel(file_name, sheet_name = my_sheet)
data = df[["ID","name","Target","Industry","description","url"]].values.tolist()

for elm in Indus:
    for d in range(len(data)):
        #print(data[d][2])
        if elm in str(data[d][3]):
            #print(str(data[d][1])+ " "+ str(elm)) 
            ActIndus.append(data[d][1])
            #print(True)


for cnt in Countries:
    for d in range(len(data)):
        #print(data[d][2])
        if cnt in str(data[d][2]):
            #print(str(data[d][1])+ " "+ str(cnt)) 
            ActCnt.append(data[d][1])
            #print(True)
            
All = ActCnt + ActIndus
All =  list(dict.fromkeys(All)) # Remove Duplicates
#print(All)

print("[+] Generating Mapped Threat Actor Reports ...") 

APTs = []


# Group Details from MITRE ATT&CK
for apt in All:
    for d in range(len(data)):
        if str(apt) == str(data[d][1]):
            #print("##########################################")
            #print("APT: ",str(data[d][1]))
            #print("Targeted Countries and regions: ",str(data[d][2]))
            #print("Sectors: ",str(data[d][3]))
            #print("Description: ",str(data[d][4]))
            Command = "wget "+str(data[d][5])+"/"+str(data[d][0])+"-enterprise-layer.json -P Navigation-Layers -q"
            APTs.append({"groupID":data[d][0],"Name":data[d][1],"Countries":data[d][2],"Sectors":data[d][3],"Description":data[d][4],"URL":data[d][5]})
            #print(Command)
            #os.system(Command) # Download ATT&CK Navigation Layers
            
print("[+] Mapped Threat Actor Reports were Generated Successfully!") 

        
data2 = []
for apt in All:
    for d in range(len(data)):
        if str(apt) == str(data[d][1]):
            data2.append(data[d])
            

#Load external data 

print("[+] Generating  additional Threat Actor Reports ...") 
with open("Threat Group Card - All groups.json","r") as f:
    groups = json.load(f)
    
# Get External Details

data3 = []

Unmapped = []

for cnt in Countries:
    for c in range(len(groups["values"])):
        try:
            if str(cnt) in str(groups["values"][c]["observed-countries"]):
                print(groups["values"][c]["tools"])
                ExtCnt.append(groups["values"][c]["actor"])
                for f in range(len(groups["values"][c]["tools"])):
                    Tools.append(groups["values"][c]["tools"][f])
                    Unmapped.append({"Actor":groups["values"][c]["actor"],"Description":groups["values"][c]["description"],"Countries":groups["values"][c]["observed-countries"],"Sectors":groups["values"][c]["observed-sectors"],"Tools":groups["values"][c]["tools"]})
                    data3.append([groups["values"][c]["actor"],groups["values"][c]["description"],groups["values"][c]["observed-countries"],groups["values"][c]["observed-sectors"]])
        except KeyError:
            pass

            
for ind in Indus:
    for i in range(len(groups["values"])):
        try:
            if str(ind) in str(groups["values"][i]["observed-sectors"]):
                print(groups["values"][i]["tools"])
                ExtIndus.append(groups["values"][i]["actor"])
                for f in range(len(groups["values"][i]["tools"])):
                    Tools.append(groups["values"][i]["tools"][f])
                    Unmapped.append({"Actor":groups["values"][i]["actor"],"Description":groups["values"][i]["description"],"Countries":groups["values"][i]["observed-countries"],"Sectors":groups["values"][i]["observed-sectors"],"Tools":groups["values"][i]["tools"]})        
                data3.append([groups["values"][i]["actor"],groups["values"][i]["description"],groups["values"][i]["observed-countries"],groups["values"][i]["observed-sectors"]])
        except KeyError:
            pass          

#print(ExtCnt)
#print(ExtIndus)
AllExt = ExtCnt + ExtIndus
ALL = AllExt + All
ALL =  list(dict.fromkeys(ALL)) # Remove Duplicates

print("[+] Threat Actor Reports were loaded Successfully!") 

df3 = pd.DataFrame(data3)

# Related Threat Reports

#Related Articles

Reports = []
print("[+] Loading Threat Reports and Articles") 

with open("vertopal.com_malpedia.json","r") as f:
    wiki = json.load(f)

for grp in All:
    for a in range(len(wiki)):
        if str(grp) in str(wiki[a]):
            #print("*****************************")
            #print("Report Title: "+str(wiki[a]["title"]))
            #print("URL: ",str(wiki[a]["URL"]))
            Reports.append({"Title":wiki[a]["title"],"URL":wiki[a]["URL"]})
   
df4 = pd.DataFrame(Reports)

print("[+] Threat Reports and Articles were loaded Successfully!") 

     
# Used Tools

Tools =  list(dict.fromkeys(Tools)) # Remove Duplicates

print("[+] Loading Threat Actors Tools and Software") 
with open("Threat Group Card - All tools.json","r") as f:
    TOOLS = json.load(f)

Ts = []
ToolsF = []

#for t in Tools:
for t in Tools:
    for T in range(len(TOOLS["values"])):
        if str(t) in str(TOOLS["values"][T]["tool"]):
            #print(TOOLS["values"][T]["tool"])
            #print(TOOLS["values"][T]["description"])
            Ts.append([TOOLS["values"][T]["tool"],TOOLS["values"][T]["description"],TOOLS["values"][T]["category"]])
            ToolsF.append({"Name":TOOLS["values"][T]["tool"],"Description":TOOLS["values"][T]["description"]})

#print(Tools[0])
#print(type(Tools[0]))

print(ToolsF[0])
print(len(ToolsF))


print("[+] Tools and Software were loaded Successfully!") 

output = template.render(APTs=APTs,Reports=Reports,Unmapped=Unmapped)
#print(output)

df5 = pd.DataFrame(Ts)
with open('Web-Report.html', 'w') as f:
    f.write(output)
    
 

print("[+] Generating the final report ...") 

df2 = pd.DataFrame(data2)
with pd.ExcelWriter('finalReport.xlsx') as writer:  
    df2.to_excel(writer, sheet_name='Mapped Groups')
    df3.to_excel(writer, sheet_name='APT Groups')
    df4.to_excel(writer, sheet_name='Threat Reports')
    df5.to_excel(writer, sheet_name='Tools')
    
print("[+] Final Report 'finalReport.xlsx' was generated successfully!") 
print("[+] Final Layers reside in 'Navigation-Layers' folder") 
print("[+] Happy Detection :) ") 

