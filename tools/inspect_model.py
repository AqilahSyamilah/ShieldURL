import joblib
m = joblib.load("model/url_phishing_model.pkl")
print("n_features_in_:", getattr(m, 'n_features_in_', None))
print("classes_:", getattr(m, 'classes_', None))
print("coef_shape:", getattr(m, 'coef_', None).shape if hasattr(m, 'coef_') else None)
print("feature_names_in_:", getattr(m, 'feature_names_in_', None))
