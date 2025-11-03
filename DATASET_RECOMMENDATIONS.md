# 📊 Kaggle Dataset Recommendations for Phishing Detection

## 🎯 **TOP RECOMMENDATION: "Phishing Website Detection Dataset"**

**Dataset Link:** [Phishing Website Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/phishing-website-detection-dataset-from-uci)

**Why This Dataset:**
- ✅ **Comprehensive Features**: 30+ features including URL-based, domain-based, and content-based features
- ✅ **Large Dataset**: 11,055 samples (5,490 legitimate, 5,565 phishing)
- ✅ **Well-Balanced**: Almost equal distribution between classes
- ✅ **Recent**: Updated and maintained
- ✅ **Research-Quality**: Used in academic research

**Features Include:**
- URL length, domain age, SSL final state
- Domain registration length, web traffic
- Page rank, Google index, links pointing to page
- Server form handler, email form handler
- Pop-up window, right-click disabled
- Iframe redirection, age of domain

---

## 🥈 **SECOND CHOICE: "Phishing Detection Dataset"**

**Dataset Link:** [Phishing Detection Dataset](https://www.kaggle.com/datasets/akashkr/phishing-dataset)

**Why This Dataset:**
- ✅ **Good Size**: 10,000+ samples
- ✅ **URL-Focused**: Primarily URL-based features
- ✅ **Clean Data**: Well-structured and labeled
- ✅ **Multiple Sources**: Combines data from various sources

---

## 🥉 **THIRD CHOICE: "Phishing Websites Features"**

**Dataset Link:** [Phishing Websites Features](https://www.kaggle.com/datasets/akashkr/phishing-websites-features)

**Why This Dataset:**
- ✅ **Feature-Rich**: 30+ engineered features
- ✅ **Balanced Classes**: Good distribution
- ✅ **URL Analysis**: Comprehensive URL parsing features

---

## 📥 **How to Download and Use**

### Step 1: Download from Kaggle
1. Go to the dataset page on Kaggle
2. Click "Download" button
3. Extract the ZIP file
4. Look for the CSV file (usually named `dataset.csv` or similar)

### Step 2: Prepare the Dataset
1. **Rename columns** to match our system:
   - Main URL column → `url`
   - Target/Label column → `label`
   
2. **Ensure proper labeling**:
   - `1` = Phishing
   - `0` = Legitimate

3. **Place in project directory**:
   ```
   phishing_detection_project/
   ├── your_dataset.csv  ← Place here
   ├── train_model.py
   ├── app.py
   └── ...
   ```

### Step 3: Update Training Script (if needed)
If your dataset has different column names, modify the `load_kaggle_dataset()` function in `train_model.py`:

```python
def load_kaggle_dataset() -> pd.DataFrame:
    # Add your dataset filename here
    possible_files = [
        "your_dataset.csv",  # ← Add your filename
        "phishing_dataset.csv",
        "phishing_websites.csv", 
        "phishing_detection.csv",
        "dataset.csv"
    ]
    
    # Add your column mapping here
    if 'your_url_column' in df.columns and 'your_label_column' in df.columns:
        df.columns = ['url', 'label']
        return df[['url', 'label']]
```

---

## 🔍 **Dataset Quality Checklist**

Before using any dataset, verify:

- [ ] **Column Names**: Has URL and label columns
- [ ] **Data Types**: URLs are strings, labels are integers
- [ ] **Missing Values**: Minimal or no missing data
- [ ] **Class Balance**: Reasonable distribution between classes
- [ ] **Data Size**: At least 1,000 samples (more is better)
- [ ] **Feature Quality**: Features are meaningful and diverse

---

## 🚀 **Quick Start with Your Dataset**

1. **Download** one of the recommended datasets
2. **Place** the CSV file in your project directory
3. **Run training**:
   ```bash
   python train_model.py
   ```
4. **Test the model**:
   ```bash
   python test_model.py
   ```
5. **Launch the web app**:
   ```bash
   streamlit run app.py
   ```

---

## 📊 **Expected Performance**

With a good dataset, you should see:
- **Accuracy**: 90%+ on test set
- **AUC-ROC**: 0.95+
- **Feature Importance**: Clear patterns in what drives decisions
- **Generalization**: Good performance on unseen URLs

---

## 🔧 **Customization Options**

### Adding New Features
If your dataset has additional features:
1. Modify `extract_comprehensive_url_features()`
2. Update feature names list
3. Retrain the model

### Using Different Models
The system supports:
- Random Forest (default)
- Gradient Boosting
- Easy to add more (SVM, Neural Networks, etc.)

---

## 📞 **Need Help?**

If you encounter issues:
1. Check the dataset format matches requirements
2. Verify column names and data types
3. Look for missing or corrupted data
4. Ensure proper labeling (0/1 values)

---

## 🎉 **Success Tips**

1. **Start with the top recommendation** - it's proven to work well
2. **Use the full dataset** - more data = better model
3. **Check feature quality** - meaningful features improve performance
4. **Validate results** - test with known legitimate/suspicious URLs
5. **Iterate and improve** - add new features or try different models

---

**Happy phishing detection! 🔒✨**
