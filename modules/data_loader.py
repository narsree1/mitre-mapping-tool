import os
import json
import traceback
import pandas as pd
import requests
import streamlit as st

def create_local_mitre_data_cache():
    """
    Create a minimal local cache of MITRE ATT&CK data that can be used
    when the online sources are unavailable.
    """
    # Check if we already have the cache file
    cache_file = 'assets/mitre_cache.json'
    
    # Ensure the assets directory exists
    os.makedirs('assets', exist_ok=True)
    
    if os.path.exists(cache_file):
        return cache_file
    
    # Create a minimal version of MITRE ATT&CK data with common techniques
    minimal_attack_data = {
        "objects": [
            # Tactics
            {
                "type": "x-mitre-tactic",
                "name": "Initial Access",
                "external_references": [{"external_id": "TA0001"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Execution",
                "external_references": [{"external_id": "TA0002"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Persistence",
                "external_references": [{"external_id": "TA0003"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Privilege Escalation",
                "external_references": [{"external_id": "TA0004"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Defense Evasion",
                "external_references": [{"external_id": "TA0005"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Credential Access",
                "external_references": [{"external_id": "TA0006"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Discovery",
                "external_references": [{"external_id": "TA0007"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Lateral Movement",
                "external_references": [{"external_id": "TA0008"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Collection",
                "external_references": [{"external_id": "TA0009"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Command and Control",
                "external_references": [{"external_id": "TA0011"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Exfiltration",
                "external_references": [{"external_id": "TA0010"}]
            },
            {
                "type": "x-mitre-tactic",
                "name": "Impact",
                "external_references": [{"external_id": "TA0040"}]
            },
            
            # Techniques - Initial Access
            {
                "type": "attack-pattern",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to victim systems.",
                "kill_chain_phases": [{"phase_name": "Initial Access"}],
                "external_references": [
                    {"external_id": "T1566", "url": "https://attack.mitre.org/techniques/T1566"}
                ]
            },
            {
                "type": "attack-pattern",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts.",
                "kill_chain_phases": [{"phase_name": "Initial Access"}, {"phase_name": "Persistence"}, {"phase_name": "Privilege Escalation"}],
                "external_references": [
                    {"external_id": "T1078", "url": "https://attack.mitre.org/techniques/T1078"}
                ]
            },
            
            # Execution
            {
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "kill_chain_phases": [{"phase_name": "Execution"}],
                "external_references": [
                    {"external_id": "T1059", "url": "https://attack.mitre.org/techniques/T1059"}
                ]
            },
            
            # Persistence
            {
                "type": "attack-pattern",
                "name": "Create Account",
                "description": "Adversaries may create an account to maintain access to victim systems.",
                "kill_chain_phases": [{"phase_name": "Persistence"}],
                "external_references": [
                    {"external_id": "T1136", "url": "https://attack.mitre.org/techniques/T1136"}
                ]
            },
            
            # Privilege Escalation
            {
                "type": "attack-pattern",
                "name": "Exploitation for Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
                "kill_chain_phases": [{"phase_name": "Privilege Escalation"}],
                "external_references": [
                    {"external_id": "T1068", "url": "https://attack.mitre.org/techniques/T1068"}
                ]
            },
            
            # Defense Evasion
            {
                "type": "attack-pattern",
                "name": "Obfuscated Files or Information",
                "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
                "kill_chain_phases": [{"phase_name": "Defense Evasion"}],
                "external_references": [
                    {"external_id": "T1027", "url": "https://attack.mitre.org/techniques/T1027"}
                ]
            },
            
            # Credential Access
            {
                "type": "attack-pattern",
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts.",
                "kill_chain_phases": [{"phase_name": "Credential Access"}],
                "external_references": [
                    {"external_id": "T1110", "url": "https://attack.mitre.org/techniques/T1110"}
                ]
            },
            
            # Discovery
            {   
                "type": "attack-pattern",
                "name": "Account Discovery",
                "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment.",
                "kill_chain_phases": [{"phase_name": "Discovery"}],
                "external_references": [
                    {"external_id": "T1087", "url": "https://attack.mitre.org/techniques/T1087"}
                ]
            },
            
            # Lateral Movement
            {
                "type": "attack-pattern",
                "name": "Lateral Tool Transfer",
                "description": "Adversaries may transfer tools or other files between systems in a compromised environment.",
                "kill_chain_phases": [{"phase_name": "Lateral Movement"}],
                "external_references": [
                    {"external_id": "T1570", "url": "https://attack.mitre.org/techniques/T1570"}
                ]
            },
            
            # Collection
            {
                "type": "attack-pattern",
                "name": "Data from Local System",
                "description": "Adversaries may target data stored on local system.",
                "kill_chain_phases": [{"phase_name": "Collection"}],
                "external_references": [
                    {"external_id": "T1005", "url": "https://attack.mitre.org/techniques/T1005"}
                ]
            },
            
            # Command and Control
            {
                "type": "attack-pattern",
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering.",
                "kill_chain_phases": [{"phase_name": "Command and Control"}],
                "external_references": [
                    {"external_id": "T1071", "url": "https://attack.mitre.org/techniques/T1071"}
                ]
            },
            
            # Exfiltration
            {
                "type": "attack-pattern",
                "name": "Exfiltration Over Alternative Protocol",
                "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
                "kill_chain_phases": [{"phase_name": "Exfiltration"}],
                "external_references": [
                    {"external_id": "T1048", "url": "https://attack.mitre.org/techniques/T1048"}
                ]
            },
            
            # Impact
            {
                "type": "attack-pattern",
                "name": "Data Encrypted for Impact",
                "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
                "kill_chain_phases": [{"phase_name": "Impact"}],
                "external_references": [
                    {"external_id": "T1486", "url": "https://attack.mitre.org/techniques/T1486"}
                ]
            }
        ]
    }
    
    # Save the minimal data to a local cache file
    with open(cache_file, 'w') as f:
        json.dump(minimal_attack_data, f)
    
    return cache_file

@st.cache_data
def load_mitre_data():
    """
    Load MITRE ATT&CK data from online sources or local cache.
    Returns:
        techniques: List of technique dictionaries
        tactic_mapping: Dictionary mapping tactic names to IDs
        tactics_list: List of tactic names
    """
    try:
        # Add headers and timeout to make the request more robust
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Try the primary URL first
        try:
            response = requests.get(
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
                headers=headers,
                timeout=30
            )
            response.raise_for_status()  # Raise an exception for 4XX/5XX responses
            attack_data = response.json()
            st.success("Successfully loaded MITRE data from primary source")
        except Exception as primary_error:
            # If primary URL fails, try a fallback URL
            try:
                st.warning(f"Primary MITRE data source failed: {primary_error}. Trying fallback source...")
                
                # Fallback to a different version/branch or a cached copy
                response = requests.get(
                    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                    headers=headers,
                    timeout=30
                )
                response.raise_for_status()
                attack_data = response.json()
                st.success("Successfully loaded MITRE data from fallback source")
            except Exception as fallback_error:
                # If both online sources fail, use the local cache
                st.warning(f"Fallback MITRE data source failed: {fallback_error}. Using local cache...")
                
                # Create and load local cache
                cache_file = create_local_mitre_data_cache()
                with open(cache_file, 'r') as f:
                    attack_data = json.load(f)
                st.info("Using locally cached MITRE data - limited technique coverage available")
        
        # Process the MITRE ATT&CK data
        techniques = []
        tactic_mapping = {}
        tactics_list = []

        # Extract tactics
        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                tactic_mapping[tactic_name] = tactic_id
                tactics_list.append(tactic_name)

        # Extract techniques (skip sub-techniques)
        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                ext_refs = obj.get('external_references', [{}])
                if not ext_refs:
                    continue
                    
                tech_id = ext_refs[0].get('external_id', 'N/A')
                if '.' in tech_id:
                    continue  # Skip sub-techniques
                
                # Get tactics for this technique
                tactic_names = []
                for phase in obj.get('kill_chain_phases', []):
                    tactic_names.append(phase.get('phase_name', ''))
                
                techniques.append({
                    'id': tech_id,
                    'name': obj.get('name', 'N/A'),
                    'description': obj.get('description', ''),
                    'tactic': ', '.join(tactic_names),
                    'tactics_list': tactic_names,
                    'url': ext_refs[0].get('url', '')
                })
        
        # Log success and data stats
        st.success(f"Successfully processed MITRE ATT&CK data: {len(techniques)} techniques, {len(tactics_list)} tactics")
        
        return techniques, tactic_mapping, tactics_list
    
    except Exception as e:
        # More detailed error reporting
        error_details = traceback.format_exc()
        st.error(f"Error loading MITRE data: {e}")
        st.error(f"Detailed error: {error_details}")
        
        # Return empty data structures as fallback
        st.warning("Using empty MITRE data as fallback. Mapping will be limited.")
        return [], {}, []

@st.cache_data
def load_library_data_with_embeddings(_model):
    """
    Load library data and compute embeddings
    
    Args:
        _model: SentenceTransformer model for creating embeddings
        
    Returns:
        library_df: DataFrame containing library data
        embeddings: Tensor of embeddings for library descriptions
    """
    try:
        # Read library.csv file
        try:
            library_df = pd.read_csv("library.csv")
        except Exception as e:
            st.warning(f"Could not load library.csv file: {e}. Starting with an empty library.")
            # Create an empty DataFrame with required columns
            library_df = pd.DataFrame(columns=['Use Case Name', 'Description', 'Log Source', 
                                              'Mapped MITRE Tactic(s)', 'Mapped MITRE Technique(s)', 
                                              'Reference Resource(s)', 'Search'])
        
        if library_df.empty:
            return None, None
        
        # Fill NaN values with placeholders
        for col in library_df.columns:
            if library_df[col].dtype == 'object':
                library_df[col] = library_df[col].fillna("N/A")
        
        # Precompute embeddings for all library entries
        descriptions = []
        for desc in library_df['Description'].tolist():
            if pd.isna(desc) or isinstance(desc, float):
                descriptions.append("No description available")  # Safe fallback
            else:
                descriptions.append(str(desc))  # Ensure it's a string
        
        # Use batching for encoding
        batch_size = 32
        all_embeddings = []
        
        for i in range(0, len(descriptions), batch_size):
            batch = descriptions[i:i+batch_size]
            batch_embeddings = _model.encode(batch, convert_to_tensor=True)
            all_embeddings.append(batch_embeddings)
        
        # Combine all embeddings
        if all_embeddings:
            embeddings = torch.cat(all_embeddings, dim=0)
            return library_df, embeddings
        
        return library_df, None
        
    except Exception as e:
        st.warning(f"Warning: Could not load library data: {e}")
        return None, None
