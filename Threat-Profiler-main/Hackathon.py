import os
import csv
import sys
import yaml
import glob
import toml
import json
import string
import requests
import pandas as pd
from pandas import read_excel 
from simple_term_menu import TerminalMenu
from jinja2 import Environment, FileSystemLoader

banner = "Automated Threat Informed Defense Assessment Tool"
print(banner)


# Initial Variables

# Read local `config.toml` file.
config = toml.load('Config/config.toml')

# Add the rquired fields in the config file (config.toml) lacated in Config Folder
Azure_AD_Tenant = config.get("Azure_AD_Tenant")
Client_ID = config.get("Client_ID")
Client_Secret = config.get("Client_Secret")
ResourceGroup = config.get("ResourceGroup")
Workspace = config.get("Workspace")
Subscription = config.get("Subscription")

Local_Path = "Resources/sigma-master/rules/"
SIGMA_CSV = "Resources/SGR.csv"
NIST_Mitigations_File = "Resources/Layers/nist800-53-r5_overview.json"
Azure_Native_Security_Controls = "Resources/Layers/Azure_platform_native_security_controls.json"
NIST_Controls_Catalog = "Resources/sp800-53r5-control-catalog.xlsx"
D3FEND_Techniques = "Resources/D3FEND/techniques.csv"
D3FEND_Defenses = "Resources/D3FEND/Defenses.csv"

Local_Queries = []
SGM = []
Rp_SIGMA = []
Rp_NIST = []
ActCnt = []
ActIndus = []
Tools = []
ExtIndus = []
ExtCnt = []
Artifacts = []
Rp_D3FEND = []
Threats = []
chunk = []


print("[+] Do you want to use an existant Threat Map (Navigation Layer)? ")
terminal_menu = TerminalMenu(
        ["Yes. Thank you", 
         "NO!"],
        multi_select=False,
        show_multi_select_hint=True,
    )

menu_entry = terminal_menu.show()

print(menu_entry)

if menu_entry == 0:

    print("[+] Enter the Threat Heat Map (Navigation Layer):")
    Navigation_Layer = input()
    #with open("Resources/ThreatMap.json","r") as r:
    with open(Navigation_Layer,"r") as r:
        threat = json.load(r)

    
    for i in range(len(threat["techniques"])):
    #print(threat["techniques"][i]["techniqueID"])
    #print(threat["techniques"][i]["tactic"])
       Threats.append(threat["techniques"][i]["techniqueID"])
    print(Threats)

elif menu_entry == 1:
    print("No")
    # Threat Profiling
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

    print("[+] Mapped Threat Intelligence Reports were Generated Successfully!") 
    # Load Group Details
    APT_Groups = "Resources/APT-groups.xlsx"
    Group_sheet = "groups"
    APT_df = read_excel(APT_Groups, sheet_name = Group_sheet)
    data = APT_df[["ID","name","Target","Industry","description","url"]].values.tolist()

    # Get the APT groups related to the provided Sectors and industries
    for elm in Indus:
        for d in range(len(data)):
            if elm in str(data[d][3]):
                ActIndus.append(data[d][1])

    # Get the APT groups related to the provided Countries or regions

    for cnt in Countries:
        for d in range(len(data)):
            if cnt in str(data[d][2]):
                ActCnt.append(data[d][1])

    # Grouping all related APTs
    All = ActCnt + ActIndus
    All =  list(dict.fromkeys(All)) # Remove Duplicates

    print(All)

    print("[+] Generating Mapped Threat Actor Reports ...") 

    APTs = []
    # Group Details from MITRE ATT&CK
    for apt in All:
        for d in range(len(data)):
            if str(apt) == str(data[d][1]):
                Command = "wget "+str(data[d][5])+"/"+str(data[d][0])+"-enterprise-layer.json -P Reports/Navigation-Layers -q"
                APTs.append({"groupID":data[d][0],"Name":data[d][1],"Countries":data[d][2],"Sectors":data[d][3],"Description":data[d][4],"URL":data[d][5]})
                os.system(Command) # Download ATT&CK Navigation Layers

    print("[+] Mapped Threat Actor Reports were Generated Successfully!") 

    Local_Path = "Reports/Navigation-Layers/" # Change it to where you store your local  ATT&CK Navigation Layers 
    Techniques = []
    Nav_Layers  = [pos_raw for pos_raw in os.listdir(Local_Path) if pos_raw.endswith('.json')]
    for layer in Nav_Layers:
        #print(layer)
        try:
            with open(Local_Path+layer,'r',) as l:
                techs = json.load(l)
        except:
            pass
        for i in range(len(techs["techniques"])):
            print(techs["techniques"][i]["techniqueID"])
            Techniques.append(techs["techniques"][i]["techniqueID"])
        

    Techniques =  list(dict.fromkeys(Techniques)) # Remove Duplicates

    for t in Techniques:
        print

    # Generate MITRE Layer

    Layer_Template = {
        "description": "Techniques Covered by Azure Sentinel Rules and Queries",
        "name": "Azure Sentinel Coverage",
        "domain": "mitre-enterprise",
        "version": "4.2",
        "techniques": 
            [{  "techniqueID": technique, "color": "#ff0000"  } for technique in Techniques] 
        ,
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff0000"
            ],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "Techniques Covered by Azure Sentinel",
                "color": "#ff0000"
            }
        ]
    }

    json_data = json.dumps(Layer_Template)

    with open("Reports/Navigation-Layers/Threat_Heatmap.json", "w") as file:
        json.dump(Layer_Template, file)

    print("[+] The MITRE matrix json file 'Threat_Heatmap.json' was created successfully")
    print("[+] The final Threat Heat Map (Navigation Layer) was Generated Successfully!") 

    #with open("Resources/ThreatMap.json","r") as r:
    with open("Reports/Threat_Heatmap.json","r") as r:
        threat = json.load(r)

    
    for i in range(len(threat["techniques"])):
    #print(threat["techniques"][i]["techniqueID"])
    #print(threat["techniques"][i]["tactic"])
       Threats.append(threat["techniques"][i]["techniqueID"])

    
print(Threats)


# Get the Access Token
Access_Url = "https://login.microsoftonline.com/"+Azure_AD_Tenant+"/oauth2/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https%3A%2F%2Fmanagement.azure.com&client_secret='+Client_Secret
print("[+] Connecting to Azure Sentinel ...")
Access_response = requests.post(Access_Url, headers=headers, data=payload).json()
Access_Token = Access_response["access_token"]
print("[+] Access Token Received Successfully")

# Techniques from Detections 

Sentinel_AlertTechniques = []

Detections_Url= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/providers/Microsoft.SecurityInsights/alertRules?api-version=2020-01-01"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

Detections_response = requests.get(Detections_Url, headers=headers2).json()
print("[+] Alert Rules Details were received Successfully")

for a in range(len(Detections_response ["value"])):
    if (str(Detections_response ["value"][a]["properties"]["displayName"]).split()[0][0]== "T"):
        Sentinel_AlertTechniques.append((str(Detections_response["value"][a]["properties"]["displayName"]).split()[0]))

print("[+] Techniques were extracted from your Azure Sentinel Analytics Successfully: ",Sentinel_AlertTechniques)


# Get covered Techniques from Hunting Queries

Hunting_Url= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/savedSearches?api-version=2020-08-01"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

Hunting_response = requests.get(Hunting_Url, headers=headers2).json()
#print(response2)
print("[+] Hunting Query Details were received from Azure Sentinel Successfully")


# Techniques from the Hunting Queries
SentinelHunt_Queries = []  
  
for t in range(len(Hunting_response["value"])):
  try:
    if (str(Hunting_response["value"][t]["properties"]["category"]) == "Hunting Queries"):
      if str(Hunting_response["value"][t]["properties"]["tags"][2]["name"]) == "techniques":
        #print(str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(",")[1])
        for k in range(len(str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(","))):
            # Add a better condition 
          SentinelHunt_Queries.append(str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(",")[k])
  except KeyError:
    pass
             
#print("Covered Hunting Techniques: ",SentinelHunt_Queries)

Total_Techniques = Sentinel_AlertTechniques + SentinelHunt_Queries

# Generate MITRE Layer

Layer_Template = {
        "description": "Techniques Covered by Azure Sentinel Rules and Queries",
        "name": "Azure Sentinel Coverage",
        "domain": "mitre-enterprise",
        "version": "4.2",
        "techniques": 
            [{  "techniqueID": technique, "color": "#ff0000"  } for technique in Total_Techniques] 
        ,
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff0000"
            ],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "Techniques Covered by Azure Sentinel",
                "color": "#ff0000"
            }
        ]
    }

json_data = json.dumps(Layer_Template)

with open("Reports/MITRE_Matrix.json", "w") as file:
    json.dump(Layer_Template, file)

print("[+] The MITRE matrix json file 'MITRE_Matrix.json' was created successfully")


#Gap Analysis 

print("[+] Threat Actor Techniques")

with open("Resources/ThreatMap.json","r") as r:
  threat = json.load(r)

Threat_Techniques = []
for i in range(len(threat["techniques"])):
  #print(threat["techniques"][i]["techniqueID"])
  #print(threat["techniques"][i]["tactic"])
  Threat_Techniques.append(threat["techniques"][i]["techniqueID"])

Watchlist = []
Watchlist0 = set(Total_Techniques)^set(Threat_Techniques)
Watchlist = list(Watchlist0)
Watchlist =  list(dict.fromkeys(Watchlist))
print(Watchlist)


with open(Azure_Native_Security_Controls,"r") as g:
  controls = json.load(g)


crt = []
results2 = []

for elm in Watchlist:
    for j in range(len(controls["techniques"])):
        if str(controls["techniques"][j]["techniqueID"]) == elm:  
          #print(elm)
          #print(controls["techniques"][j]["metadata"])
          for o in controls["techniques"][j]["metadata"]:
            if not "divide" in str(o):
              crt.append({"TechniqueID":elm,"ControlDetails":o})
              #print(o)

#print(crt[15])
for c in crt:
  chunk.append(c)
  if len(chunk) == 4:
    results2.append(chunk)
    chunk = []

print(results2)


# D3FEND

with open(D3FEND_Techniques, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    print("[+] D3FEND Techniques and Artifacts were loaded Successfully")
    for row in reader:
        for i in Watchlist:
            if str(i) == str(row['ATTACKid']):
                #print(row)
                #print(row['ATTACKid'])
                for artf in list(row.values())[2:]:
                        Artifacts.append(artf)

while '' in Artifacts:
   Artifacts.remove('')   #Deletes empty elements

Artifacts = list(dict.fromkeys(Artifacts)) #Deletes Duplicates

print("[+] Related D3FEND Artifacts were extracted Successfully")                              
#print(Artifacts)        

Total_Artifacts= []

for f in Artifacts:
    #print(f.strip('][').split(', '))
    for g in range(len(f.strip('][').split(', '))):
        Total_Artifacts.append(f.strip('][').replace("'",'').split(', ')[g])


Total_Artifacts = list(dict.fromkeys(Total_Artifacts)) #Deletes Duplicates
#print(G[0])
for t in Total_Artifacts:
    t.translate({ord(c): None for c in string.whitespace})

print("[+] Related D3FEND Artifacts were extracted Successfully")        
#print(Total_Artifacts)

Defenses = []

with open(D3FEND_Defenses, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    print("[+] D3FEND Defenses were loaded Successfully")  
    print("[+] Related D3FEND Defenses are the following") 
    for row in reader:
        for Art in Total_Artifacts:
            if str(Art) in str(row):
                 #print(row['DEFENDid'])
                 #Defenses.append(row['DEFENDid'])
                 Rp_D3FEND.append({
                            "ID":row['DEFENDid'],
                            "Defense":row['Defense'],
                            "Definition":row['Definition'],
                            "Analyzes":row['Analyzes'],
                            "Neutralizes":row['Neutralizes'],
                            "Verifies":row['Verifies'],
                            "Obfuscates":row['Obfuscates'],
                            "Filters":row['Filters'],
                            "Encrypts":row['Encrypts'],
                            "Blocks":row['Blocks'],
                            "Authenticates":row['Authenticates'],
                            "Terminates":row['Terminates'],
                            "Isolates":row['Isolates'],
                            "Spoofs":row['Spoofs'],
                            "Disables":row['Disables'],
                            "Modifies":row['Modifies']
                        })
Defenses = list(dict.fromkeys(Defenses)) #Deletes Duplicates

#print(Rp_D3FEND)
#print(Rp_D3FEND[0])


D3FEND_Links = []
for D in Rp_D3FEND:
    #print("https://d3fend.mitre.org/technique/d3f:"+str(D["Defense"]).translate({ord(c): None for c in string.whitespace}))
    D3FEND_Links.append("https://d3fend.mitre.org/technique/d3f:"+str(D["Defense"]).translate({ord(c): None for c in string.whitespace}))


D3FEND_Links = list(dict.fromkeys(D3FEND_Links)) #Deletes Duplicates

for f in D3FEND_Links:
    print(f)

# Get Related NIST Mitigations

print("[+] Related NIST MITIGATIONS")

with open(NIST_Mitigations_File,"r") as r:
  NIST = json.load(r)

df_NIST = read_excel(NIST_Controls_Catalog)
NIST_Info = df_NIST[["Control Identifier","Control (or Control Enhancement) Name","Control Text"]].to_dict() 

for elm in Watchlist:
    for j in range(len(NIST["techniques"])):
        if str(NIST["techniques"][j]["techniqueID"]) == elm:
            print(NIST["techniques"][j]["tactic"])
            print(NIST["techniques"][j]["techniqueID"])
            Mitlist = str(NIST["techniques"][j]["comment"]).replace("Mitigated by","").translate({ord(c): None for c in string.whitespace}).split(",")
            print(Mitlist)
            print("##################")
            for m in Mitlist:
                for Inf in range(len(NIST_Info["Control Identifier"])):
                    if str(m+"(") in str(NIST_Info["Control Identifier"][Inf]) or (str(m) == str(NIST_Info["Control Identifier"][Inf])):
                        print(NIST_Info["Control Identifier"][Inf])
                        Rp_NIST.append({"Technique":elm,"Control":NIST_Info["Control Identifier"][Inf],"Name":NIST_Info["Control (or Control Enhancement) Name"][Inf],"Comment":NIST_Info["Control Text"][Inf]})


print(Rp_NIST)

# Get Related SIGMA Rules

print("[+] Related SIGMA Rules")

if os.path.isfile(SIGMA_CSV) == False:
  print("[+] The local list of SIGMA rules does not exists. Thus, we are creating a new one ...")
  for rule in glob.iglob(Local_Path  + '**/**', recursive=True):
    if rule.endswith('.yml'): 
      print(rule)
      with open(rule,'r',encoding='utf-8') as q: #errors='ignore'
        try:
          yaml_query = yaml.load(q, Loader=yaml.FullLoader)
          for j in range(len(yaml_query["tags"])):
            print("[+] "+ (str(yaml_query["tags"][j]).replace("t","T")) +" "+str(rule))
            SGM.append({"Techniques":str(yaml_query["tags"][j]).replace("t","T"),"Rule":str(rule)})
            
        except:
          pass
          
  df = pd.DataFrame(SGM)       
  df.to_csv('Resources/SGR.csv') 

else:
  with open(SIGMA_CSV,'r') as ru:
    rules = csv.reader(ru, delimiter=',')
    #for W in range(len(Watchlist)):
    for row in rules:
      for W in Watchlist:
        if W in str(row):
          print(row[1:])
          Rp_SIGMA.append({"Techniques":row[1],"Rule":row[2]})

print(Rp_SIGMA)

# Get Related Atomic Tests

print("[+] Related Atomic Tests")

with open("Resources/Layers/art-navigator-layer.json","r") as r:
  Atomic_Tests = json.load(r)

Atomic_Tests_Techniques = []
for i in range(len(Atomic_Tests["techniques"])):
  Atomic_Tests_Techniques.append(Atomic_Tests["techniques"][i]["techniqueID"])

Atomic_Tests_Techniques = list(dict.fromkeys(Atomic_Tests_Techniques)) #Deletes Duplicates

Rp_Atomics =  []

for atomic_technique in Atomic_Tests_Techniques:
  for W in Watchlist:
    if str(W) == str(atomic_technique):
      print(str(W),": ","https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"+str(W)+"/"+str(W)+".md")
      Rp_Atomics.append({"Technique":W,"URL":"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"+str(W)+"/"+str(W)+".md"})

