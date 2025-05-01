# MITRE ATT&CK Mapping Tool

A web-based tool that automatically maps security use cases to the MITRE ATT&CK framework using natural language processing and similarity matching.

## Features

- **Automatic Mapping**: Map security use cases to MITRE ATT&CK tactics and techniques using NLP
- **Library Matching**: Match against previously mapped use cases for higher accuracy
- **Suggestions**: Get suggestions for additional use cases based on your log sources
- **Analytics**: Visualize your security coverage across the MITRE ATT&CK framework
- **Export**: Generate MITRE ATT&CK Navigator layers for visualization

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/mitre-mapping-tool.git
cd mitre-mapping-tool
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run app.py
```

## Usage

1. Upload a CSV file containing your security use cases with the following columns:
   - Use Case Name
   - Description
   - Log Source

2. Click "Start Mapping" to process your use cases

3. Navigate through the app to see:
   - Results: Filtered view of mapped use cases
   - Analytics: Visualizations of your ATT&CK coverage
   - Suggestions: Additional use cases based on your log sources
   - Export: Generate and download Navigator layer files

## Technical Details

The application uses:
- **BGE Embeddings**: BAAI/bge-base-en-v1.5 model for semantic similarity
- **Streamlit**: Web interface
- **PyTorch**: Tensor operations for efficient similarity calculations
- **Plotly**: Interactive visualizations
- **MITRE ATT&CK API**: Latest framework data with fallback mechanisms

## Requirements

- Python 3.8+
- Streamlit 1.24.0+
- PyTorch 2.0.0+
- Sentence Transformers 2.2.2+
- See requirements.txt for full dependencies

## Project Structure

```
mitre-mapping-tool/
│
├── app.py                   # Main application file
├── requirements.txt         # Dependencies
├── README.md                # Project documentation
│
├── modules/                 # Modular components
│   ├── __init__.py          # Makes modules a package
│   ├── data_loader.py       # Data loading functions
│   ├── embedding.py         # Embedding model and functions
│   ├── mapper.py            # Mapping logic
│   ├── visualizations.py    # Charts and visualization
│   ├── utils.py             # Helper functions
│   └── styles.css           # Custom CSS styles
│
└── assets/                  # Static assets
    └── mitre_cache.json     # Local MITRE ATT&CK data cache
```

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) for the framework
- [Beijing Academy of Artificial Intelligence](https://www.baai.ac.cn/english.html) for the BGE embedding model
- [Sentence Transformers](https://www.sbert.net/) library for embeddings
