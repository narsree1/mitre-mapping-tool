import datetime
import json
import uuid
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

def create_metrics_display(num_use_cases, covered_techniques, coverage_percent, library_matches, model_matches):
    """
    Create HTML for metrics display cards
    
    Args:
        num_use_cases: Number of security use cases
        covered_techniques: Number of MITRE techniques covered
        coverage_percent: Percentage of framework coverage
        library_matches: Number of library matches
        model_matches: Number of model-based matches
    """
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{num_use_cases}</div>
            <div class="metric-label">Security Use Cases</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{covered_techniques}</div>
            <div class="metric-label">Mapped Techniques</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{coverage_percent}%</div>
            <div class="metric-label">Framework Coverage</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{library_matches} / {model_matches}</div>
            <div class="metric-label">Library Matches / Model Matches</div>
        </div>
        """, unsafe_allow_html=True)

def create_source_chart(df):
    """
    Create a pie chart showing distribution of mapping sources
    
    Args:
        df: DataFrame containing mapping results
        
    Returns:
        fig: Plotly figure object or None if no data
    """
    # Handle empty or all-NaN columns
    if df is None or 'Match Source' not in df.columns or df['Match Source'].isna().all():
        return None
        
    match_source_counts = df['Match Source'].fillna('Unknown').value_counts().reset_index()
    match_source_counts.columns = ['Source', 'Count']
    
    # Create chart only if there's data
    if not match_source_counts.empty:
        fig_source = px.pie(
            match_source_counts, 
            values='Count', 
            names='Source',
            title="Distribution of Mapping Sources",
            hole=0.5,
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        
        fig_source.update_layout(
            legend=dict(orientation="h", yanchor="bottom", y=-0.2)
        )
        return fig_source
    
    return None

def create_tactic_chart(df):
    """
    Create a doughnut chart showing coverage by tactic
    
    Args:
        df: DataFrame containing mapping results
        
    Returns:
        fig: Plotly figure object or None if no data
    """
    if df is None or 'Mapped MITRE Tactic(s)' not in df.columns:
        return None
        
    # Create data for tactic coverage
    tactic_counts = {}
    for _, row in df.iterrows():
        tactic_str = row.get('Mapped MITRE Tactic(s)', '')
        if pd.isna(tactic_str):
            continue
            
        for tactic in str(tactic_str).split(', '):
            if tactic and tactic != 'N/A':
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    
    # Transform to dataframe for visualization
    tactic_df = pd.DataFrame({
        'Tactic': list(tactic_counts.keys()),
        'Use Cases': list(tactic_counts.values())
    }).sort_values('Use Cases', ascending=False)
    
    if not tactic_df.empty:
        # Create doughnut chart for tactic coverage with better colors
        fig_tactic = go.Figure(data=[go.Pie(
            labels=tactic_df['Tactic'],
            values=tactic_df['Use Cases'],
            hole=.5,
            textposition='outside',  # This ensures all labels are outside
            textinfo='label+percent',
            marker=dict(colors=px.colors.qualitative.Dark24)  # Using Dark24 for better contrast
        )])
        
        fig_tactic.update_layout(
            title="Security Use Cases by MITRE Tactic",
            showlegend=False,  # Remove legend to prevent overlap
            margin=dict(t=50, b=50, l=100, r=100)  # Margin for external labels
        )
        
        return fig_tactic
    
    return None

def create_technique_chart(df, techniques_count, mitre_techniques):
    """
    Create a doughnut chart showing coverage by technique
    
    Args:
        df: DataFrame containing mapping results
        techniques_count: Dictionary counting occurrences of each technique
        mitre_techniques: List of MITRE technique dictionaries
        
    Returns:
        fig: Plotly figure object or None if no data
    """
    if not techniques_count:
        return None
        
    # Get top techniques for the chart (limiting to top 10 for readability)
    technique_ids = list(techniques_count.keys())
    technique_counts = list(techniques_count.values())
    
    # Get technique names - with improved extraction to fix "Multi:unknown" issue
    technique_names = []
    for tech_id in technique_ids:
        # Find the full technique information in the processed data
        full_tech_info = None
        for _, row in df.iterrows():
            technique = row.get('Mapped MITRE Technique(s)', '')
            if not pd.isna(technique) and tech_id in technique:
                full_tech_info = technique
                break
        
        # If found in the data, use the full name; otherwise, look for it in mitre_techniques
        if full_tech_info:
            technique_names.append(full_tech_info)
        else:
            tech_name = next((t['name'] for t in mitre_techniques if t['id'] == tech_id), tech_id)
            technique_names.append(f"{tech_id} - {tech_name}")
    
    technique_df = pd.DataFrame({
        'Technique': technique_names,
        'Count': technique_counts
    }).sort_values('Count', ascending=False).head(10)
    
    # Create doughnut chart for technique coverage with better colors
    fig_tech = go.Figure(data=[go.Pie(
        labels=technique_df['Technique'],
        values=technique_df['Count'],
        hole=.5,
        textposition='outside',  # This ensures all labels are outside
        textinfo='label+percent',
        marker=dict(colors=px.colors.qualitative.Bold)  # Using Bold color scheme for better contrast
    )])
    
    fig_tech.update_layout(
        title="Top 10 MITRE Techniques in Security Use Cases",
        showlegend=False,  # Remove legend to prevent overlap
        margin=dict(t=50, b=50, l=100, r=100)  # Margin for external labels
    )
    
    return fig_tech

def create_navigator_layer(techniques_count):
    """
    Create a MITRE ATT&CK Navigator layer from technique count data
    
    Args:
        techniques_count: Dictionary counting occurrences of each technique
        
    Returns:
        layer_json: JSON string of Navigator layer
        layer_id: Unique ID for the layer
    """
    try:
        techniques_data = []
        for tech_id, count in techniques_count.items():
            techniques_data.append({
                "techniqueID": tech_id,
                "score": count,
                "color": "",
                "comment": f"Count: {count}",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })
        
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        layer_id = str(uuid.uuid4())
        
        layer = {
            "name": f"Security Use Cases Mapping - {current_date}",
            "versions": {
                "attack": "17",
                "navigator": "4.8.1",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": f"Mapping of security use cases to MITRE ATT&CK techniques, generated on {current_date}",
            "filters": {
                "platforms": ["Linux", "macOS", "Windows", "Network", "PRE", "Containers", "Office 365", "SaaS", "IaaS", "Google Workspace", "Azure AD"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": techniques_data,
            "gradient": {
                "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
                "minValue": 0,
                "maxValue": max(techniques_count.values()) if techniques_count else 1
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }
        
        return json.dumps(layer, indent=2), layer_id
    except Exception as e:
        st.error(f"Error creating Navigator layer: {e}")
        return "{}", ""
