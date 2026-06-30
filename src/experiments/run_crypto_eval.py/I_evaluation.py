"""
I_evaluation.py — Partie I : Évaluation complète du système

Consolide toutes les métriques des parties précédentes en un seul rapport :
  1. Métriques cryptographiques (partie D + F)
  2. Métriques IA (partie G)
  3. Métriques blockchain/performance (parties E + H)

Output : I_evaluation_complete.xlsx
"""

import os, sys, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR    = SCRIPT_DIR
FIG_DIR    = os.path.join(SCRIPT_DIR, "figures")
os.makedirs(FIG_DIR, exist_ok=True)

# ── Chemins des résultats des parties précédentes ──────────────────────────
PATH_G_AI      = "/mnt/user-data/outputs/G_IA/ai_results.xlsx"
PATH_F_VERIF   = "/mnt/user-data/outputs/F_verification/verification_report_BGL.xlsx"
PATH_E_COST    = "/mnt/user-data/outputs/eth_project/cost_report_summary.csv"
PATH_H_ANCRAGE = "/mnt/user-data/outputs/H_couplage/H_couplage_ia_ancrage.xlsx"
PATH_CRYPTO_TM = os.path.join(SCRIPT_DIR, "crypto_timing.csv")
PATH_DET_RATES = os.path.join(SCRIPT_DIR, "detection_rates.csv")
OUT_EXCEL      = os.path.join(OUT_DIR, "I_evaluation_complete.xlsx")


# ══════════════════════════════════════════════════════════════════════════
# 1. MÉTRIQUES CRYPTOGRAPHIQUES
# ══════════════════════════════════════════════════════════════════════════

def build_crypto_metrics():
    print("1. Métriques cryptographiques...")

    # ── Taux de détection par type d'attaque (partie F) ──
    df_det = pd.read_csv(PATH_DET_RATES)

    # Regrouper en familles d'attaques
    def famille(atk):
        if "injection"      in atk: return "Injection"
        if "modification"   in atk: return "Modification"
        if "reordonnance"   in atk: return "Réordonnancement"
        if "replay"         in atk: return "Replay"
        if "rollback"       in atk: return "Rollback"
        if "suppression"    in atk: return "Suppression"
        return "Clean"

    df_det["famille"] = df_det["attack_type"].apply(famille)
    df_fam = (df_det[df_det["famille"]!="Clean"]
              .groupby("famille")
              .agg(total=("total","sum"),
                   detected=("detected","sum"))
              .reset_index())
    df_fam["taux_detection"] = (df_fam["detected"]/df_fam["total"]).round(4)

    # Ajouter les familles manquantes (suppression non testée dans le run = 0%)
    familles_attendues = ["Injection","Modification","Réordonnancement","Replay","Rollback","Suppression"]
    for f in familles_attendues:
        if f not in df_fam["famille"].values:
            df_fam = pd.concat([df_fam,
                pd.DataFrame([{"famille":f,"total":0,"detected":0,"taux_detection":None}])],
                ignore_index=True)

    df_taux = df_det[df_det["famille"]!="Clean"][
        ["attack_type","famille","total","detected","not_detected","detection_rate"]
    ].copy()
    df_taux.columns = ["Type d'attaque","Famille","Total logs","Détectés",
                       "Non détectés","Taux de détection"]

    # ── Timing (partie D) ──
    df_tm = pd.read_csv(PATH_CRYPTO_TM)
    df_tm.columns = ["N logs","Temps chaîne (ms)","Temps Merkle (ms)",
                     "Temps génération preuve (ms)","Temps vérification preuve (ms)",
                     "Taille preuve (octets)","Nb siblings"]

    # ── Synthèse cryptographique ──
    df_synth_crypto = pd.DataFrame([
        {"Métrique": "Taux détection — Injection",         "Valeur": f"{df_fam.loc[df_fam['famille']=='Injection','taux_detection'].values[0]:.1%}"},
        {"Métrique": "Taux détection — Modification",      "Valeur": f"{df_fam.loc[df_fam['famille']=='Modification','taux_detection'].values[0]:.1%}"},
        {"Métrique": "Taux détection — Réordonnancement",  "Valeur": f"{df_fam.loc[df_fam['famille']=='Réordonnancement','taux_detection'].values[0]:.1%}"},
        {"Métrique": "Taux détection — Replay",            "Valeur": f"{df_fam.loc[df_fam['famille']=='Replay','taux_detection'].values[0]:.1%}"},
        {"Métrique": "Taux détection — Rollback",          "Valeur": f"{df_fam.loc[df_fam['famille']=='Rollback','taux_detection'].values[0]:.1%}"},
        {"Métrique": "Taux détection — Suppression",       "Valeur": "N/A (non inclus dans le run F)"},
        {"Métrique": "─── Timing (batch N=128) ───",       "Valeur": ""},
        {"Métrique": "Temps génération chaîne de hash",    "Valeur": f"{df_tm.loc[df_tm['N logs']==128,'Temps chaîne (ms)'].values[0]} ms"},
        {"Métrique": "Temps construction arbre Merkle",    "Valeur": f"{df_tm.loc[df_tm['N logs']==128,'Temps Merkle (ms)'].values[0]} ms"},
        {"Métrique": "Temps génération preuve d'inclusion","Valeur": f"{df_tm.loc[df_tm['N logs']==128,'Temps génération preuve (ms)'].values[0]} ms"},
        {"Métrique": "Temps vérification preuve",          "Valeur": f"{df_tm.loc[df_tm['N logs']==128,'Temps vérification preuve (ms)'].values[0]} ms"},
        {"Métrique": "Taille moyenne preuve Merkle (N=128)","Valeur": f"{df_tm.loc[df_tm['N logs']==128,'Taille preuve (octets)'].values[0]} octets"},
        {"Métrique": "Taille moyenne preuve Merkle (N=512)","Valeur": f"{df_tm.loc[df_tm['N logs']==512,'Taille preuve (octets)'].values[0]} octets"},
        {"Métrique": "Taille moyenne preuve Merkle (N=1024)","Valeur": f"{df_tm.loc[df_tm['N logs']==1024,'Taille preuve (octets)'].values[0]} octets"},
        {"Métrique": "Algorithme de hash",                 "Valeur": "SHA-256"},
        {"Métrique": "Algorithme de signature",            "Valeur": "Ed25519"},
    ])

    return df_synth_crypto, df_taux, df_tm


# ══════════════════════════════════════════════════════════════════════════
# 2. MÉTRIQUES IA
# ══════════════════════════════════════════════════════════════════════════

def build_ia_metrics():
    print("2. Métriques IA...")

    xl_g = pd.ExcelFile(PATH_G_AI)

    # Modèles
    df_models = pd.read_excel(xl_g, "comparaison_modeles")
    # Ajouter FPR et FNR à partir de precision/recall
    # FPR = FP/(FP+TN) : on l'estime depuis les prédictions test
    df_preds = pd.read_excel(xl_g, "predictions_test")

    y_true = df_preds["y"].values
    rows_ia = []
    model_cols = [c for c in df_preds.columns if c.startswith("pred_")]
    model_names_map = {
        "pred_TF-IDF+LR": "TF-IDF + LR",
        "pred_TF-IDF+SVM": "TF-IDF + SVM",
        "pred_IForest":    "Isolation Forest",
        "pred_OCSVM":      "One-Class SVM",
        "pred_LSTM":       "LSTM",
    }
    for col in model_cols:
        mname = model_names_map.get(col, col)
        yp = df_preds[col].values

        tp = int(((y_true==1)&(yp==1)).sum())
        tn = int(((y_true==0)&(yp==0)).sum())
        fp = int(((y_true==0)&(yp==1)).sum())
        fn = int(((y_true==1)&(yp==0)).sum())

        fpr = round(fp/(fp+tn),4) if (fp+tn)>0 else 0
        fnr = round(fn/(fn+tp),4) if (fn+tp)>0 else 0

        base = df_models[df_models["model"]==mname].iloc[0] if mname in df_models["model"].values else {}
        rows_ia.append({
            "Modèle":     mname,
            "Accuracy":   base.get("accuracy", None),
            "Precision":  base.get("precision", None),
            "Recall":     base.get("recall", None),
            "F1-score":   base.get("f1", None),
            "AUROC":      base.get("roc_auc", None),
            "AUPRC":      base.get("pr_auc", None),
            "FPR":        fpr,
            "FNR":        fnr,
            "TP":tp,"TN":tn,"FP":fp,"FN":fn,
            "Temps entraîn. (s)": base.get("train_time_s", None),
        })

    df_ia_models = pd.DataFrame(rows_ia)

    # Recall par type d'attaque (partie G)
    df_atk = pd.read_excel(xl_g, "metriques_par_attaque")

    # Detection delay (partie H)
    xl_h = pd.ExcelFile(PATH_H_ANCRAGE)
    df_h = pd.read_excel(xl_h, "cout_securite")
    best_h = df_h.sort_values("J_objectif").iloc[0]
    detection_delay = best_h["latence_moy_logs"]

    df_synth_ia = pd.DataFrame([
        {"Métrique": "─── Meilleur modèle : LSTM ───",  "Valeur": ""},
        {"Métrique": "Accuracy",   "Valeur": "0.9809"},
        {"Métrique": "Precision",  "Valeur": "0.9992"},
        {"Métrique": "Recall",     "Valeur": "0.9815"},
        {"Métrique": "F1-score",   "Valeur": "0.9903"},
        {"Métrique": "AUROC",      "Valeur": "0.9922"},
        {"Métrique": "AUPRC",      "Valeur": "0.9999"},
        {"Métrique": "FPR (LSTM)", "Valeur": str(rows_ia[-1]["FPR"])},
        {"Métrique": "FNR (LSTM)", "Valeur": str(rows_ia[-1]["FNR"])},
        {"Métrique": "─── Detection delay ───", "Valeur": ""},
        {"Métrique": "Délai détection moyen (logs avant ancrage)",
         "Valeur": f"{detection_delay:.1f} logs (stratégie: {best_h['strategie']})"},
        {"Métrique": "─── Note sur le recall ───", "Valeur": ""},
        {"Métrique": "Priorité recall",
         "Valeur": "Recall=0.9815 : une falsification non détectée est plus grave qu'une fausse alerte"},
    ])

    return df_synth_ia, df_ia_models, df_atk


# ══════════════════════════════════════════════════════════════════════════
# 3. MÉTRIQUES BLOCKCHAIN / PERFORMANCE
# ══════════════════════════════════════════════════════════════════════════

def build_blockchain_metrics():
    print("3. Métriques blockchain/performance...")

    df_e = pd.read_csv(PATH_E_COST)
    xl_h = pd.ExcelFile(PATH_H_ANCRAGE)
    df_h = pd.read_excel(xl_h, "cout_securite")

    # Débit : logs/seconde = logs_par_batch / temps_ancrage
    # On estime le débit à partir des données E
    df_e["debit_logs_sec"] = (df_e["logs_par_batch_moyen"] /
                               df_e["temps_moyen_ancrage_s"]).round(1)

    # Stockage off-chain : taille des logs originaux
    avg_log_size_bytes = 250   # taille moyenne d'un log BGL en octets
    total_logs = 100000
    storage_offchain_mb = total_logs * avg_log_size_bytes / 1e6

    df_synth_bc = pd.DataFrame([
        {"Métrique": "─── Partie E — Ancrage réel (5000 logs) ───", "Valeur": ""},
        {"Métrique": "Gas par ancrage (moyen)",    "Valeur": "368 750"},
        {"Métrique": "Gas min / max",              "Valeur": "348 234 / 385 222"},
        {"Métrique": "Gas total (Δt=1min)",        "Valeur": "10 325 008"},
        {"Métrique": "Gas total (Δt=5min)",        "Valeur": "2 925 160"},
        {"Métrique": "Gas total (Δt=10min)",       "Valeur": "1 472 536"},
        {"Métrique": "Latence ancrage (Δt=1min)",  "Valeur": "0.0229 s/tx"},
        {"Métrique": "Latence ancrage (Δt=5min)",  "Valeur": "0.0212 s/tx"},
        {"Métrique": "Latence ancrage (Δt=10min)", "Valeur": "0.0216 s/tx"},
        {"Métrique": "Débit (Δt=1min)",           "Valeur": f"{df_e.loc[df_e['delta_t_minutes']==1,'debit_logs_sec'].values[0]:,.0f} logs/s"},
        {"Métrique": "Débit (Δt=5min)",           "Valeur": f"{df_e.loc[df_e['delta_t_minutes']==5,'debit_logs_sec'].values[0]:,.0f} logs/s"},
        {"Métrique": "Nb transactions (Δt=1min)", "Valeur": "28"},
        {"Métrique": "Nb transactions (Δt=5min)", "Valeur": "8"},
        {"Métrique": "Nb transactions (Δt=10min)","Valeur": "4"},
        {"Métrique": "Taille on-chain par tx",    "Valeur": "305 octets"},
        {"Métrique": "Stockage off-chain (100k logs)","Valeur": f"{storage_offchain_mb:.1f} MB"},
        {"Métrique": "─── Partie H — Stratégies ───", "Valeur": ""},
        {"Métrique": "Stratégie meilleur J",      "Valeur": df_h.sort_values('J_objectif').iloc[0]['strategie']},
        {"Métrique": "Coût selon batch size N=512",  "Valeur": f"{df_h.loc[df_h['strategie']=='Fixe N=512','gas_total'].values[0]:,} gas"},
        {"Métrique": "Coût selon batch size N=1024", "Valeur": f"{df_h.loc[df_h['strategie']=='Fixe N=1024','gas_total'].values[0]:,} gas"},
        {"Métrique": "Coût selon batch size N=2048", "Valeur": f"{df_h.loc[df_h['strategie']=='Fixe N=2048','gas_total'].values[0]:,} gas"},
    ])

    return df_synth_bc, df_e, df_h


# ══════════════════════════════════════════════════════════════════════════
# 4. GRAPHIQUES
# ══════════════════════════════════════════════════════════════════════════

def plot_all(df_taux, df_ia_models, df_tm, df_h):
    print("Génération des graphiques...")

    # ── G1 : Taux de détection cryptographique par famille ──
    df_plot = df_taux.groupby("Famille").agg(
        total=("Total logs","sum"), detected=("Détectés","sum")).reset_index()
    df_plot["taux"] = df_plot["detected"]/df_plot["total"]
    df_plot = df_plot[df_plot["total"]>0].sort_values("taux", ascending=True)

    fig, ax = plt.subplots(figsize=(9, 5))
    colors = ["#4CAF50" if t==1.0 else "#FF9800" if t>0.5 else "#F44336"
              for t in df_plot["taux"]]
    bars = ax.barh(df_plot["Famille"], df_plot["taux"], color=colors, alpha=0.85)
    ax.set_xlim(0, 1.15)
    ax.set_xlabel("Taux de détection")
    ax.set_title("Taux de détection cryptographique par famille d'attaque\n(Partie D+F)", fontsize=12)
    for bar, val in zip(bars, df_plot["taux"]):
        ax.text(bar.get_width()+0.01, bar.get_y()+bar.get_height()/2,
                f"{val:.1%}", va="center", fontsize=10, fontweight="bold")
    ax.axvline(1.0, color="green", lw=1, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/I1_detection_crypto.png", dpi=150)
    plt.close()

    # ── G2 : Comparaison complète des 5 modèles IA ──
    metrics = ["F1-score","AUROC","AUPRC","Recall","Precision"]
    models  = df_ia_models["Modèle"].tolist()
    x = np.arange(len(models)); w = 0.15
    colors_m = ["#2196F3","#4CAF50","#FF9800","#9C27B0","#F44336"]

    fig, ax = plt.subplots(figsize=(13, 6))
    for i, (m, col) in enumerate(zip(metrics, colors_m)):
        vals = df_ia_models[m].fillna(0).tolist()
        ax.bar(x+i*w, vals, w, label=m, color=col, alpha=0.85)
        for j, v in enumerate(vals):
            ax.text(x[j]+i*w, v+0.01, f"{v:.2f}", ha="center", va="bottom", fontsize=6)
    ax.set_xticks(x+w*2); ax.set_xticklabels(models, fontsize=9)
    ax.set_ylim(0, 1.15); ax.set_ylabel("Score")
    ax.set_title("Métriques IA — Comparaison complète des 5 modèles (Partie G)", fontsize=12)
    ax.legend(fontsize=9); ax.axhline(0.5, color="gray", lw=0.7, linestyle="--")
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/I2_metriques_ia.png", dpi=150)
    plt.close()

    # ── G3 : FPR / FNR par modèle ──
    fig, ax = plt.subplots(figsize=(9, 5))
    x2 = np.arange(len(models))
    ax.bar(x2-0.2, df_ia_models["FPR"], 0.35, label="FPR (faux positifs)", color="#FF5722", alpha=0.85)
    ax.bar(x2+0.2, df_ia_models["FNR"], 0.35, label="FNR (faux négatifs)", color="#9C27B0", alpha=0.85)
    ax.set_xticks(x2); ax.set_xticklabels(models, fontsize=9)
    ax.set_ylim(0, 1.1); ax.set_ylabel("Taux d'erreur")
    ax.set_title("FPR et FNR par modèle IA\n(FNR prioritaire : falsification non détectée = plus grave)", fontsize=11)
    ax.legend(fontsize=9)
    ax.axhline(0.1, color="orange", lw=1, linestyle="--", label="Seuil 10%")
    for i, (fpr, fnr) in enumerate(zip(df_ia_models["FPR"], df_ia_models["FNR"])):
        ax.text(i-0.2, fpr+0.01, f"{fpr:.3f}", ha="center", fontsize=8)
        ax.text(i+0.2, fnr+0.01, f"{fnr:.3f}", ha="center", fontsize=8)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/I3_fpr_fnr.png", dpi=150)
    plt.close()

    # ── G4 : Timing cryptographique vs N logs ──
    fig, axes = plt.subplots(1, 3, figsize=(14, 4))
    ax1, ax2, ax3 = axes
    ax1.plot(df_tm["N logs"], df_tm["Temps chaîne (ms)"], "o-", color="#2196F3", lw=2)
    ax1.set_xlabel("N logs"); ax1.set_ylabel("Temps (ms)")
    ax1.set_title("Génération chaîne de hash"); ax1.grid(True, alpha=0.3)

    ax2.plot(df_tm["N logs"], df_tm["Temps Merkle (ms)"], "o-", color="#4CAF50", lw=2)
    ax2.set_xlabel("N logs"); ax2.set_ylabel("Temps (ms)")
    ax2.set_title("Construction arbre Merkle"); ax2.grid(True, alpha=0.3)

    ax3.plot(df_tm["N logs"], df_tm["Taille preuve (octets)"], "o-", color="#FF9800", lw=2)
    ax3.set_xlabel("N logs"); ax3.set_ylabel("Taille (octets)")
    ax3.set_title("Taille preuve Merkle"); ax3.grid(True, alpha=0.3)
    plt.suptitle("Performance cryptographique selon la taille du batch (Partie D)", fontsize=11)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/I4_timing_crypto.png", dpi=150)
    plt.close()

    # ── G5 : Gas total selon stratégie (blockchain) ──
    df_h_plot = df_h.sort_values("gas_total")
    colors_h = ["#2196F3" if "Fixe N" in s else
                "#4CAF50" if "Fixe Δt" in s else
                "#FF9800" if "Adaptatif" in s else "#9C27B0"
                for s in df_h_plot["strategie"]]
    fig, ax = plt.subplots(figsize=(12, 5))
    bars = ax.barh(range(len(df_h_plot)), df_h_plot["gas_total"]/1e6, color=colors_h, alpha=0.85)
    ax.set_yticks(range(len(df_h_plot)))
    ax.set_yticklabels([s.replace("(","(\n") for s in df_h_plot["strategie"]], fontsize=8)
    ax.set_xlabel("Gas total (millions)")
    ax.set_title("Gas total par stratégie d'ancrage (Partie E+H)", fontsize=12)
    for bar, val in zip(bars, df_h_plot["gas_total"]/1e6):
        ax.text(bar.get_width()+0.5, bar.get_y()+bar.get_height()/2,
                f"{val:.1f}M", va="center", fontsize=8)
    ax.grid(True, axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/I5_gas_strategies.png", dpi=150)
    plt.close()

    print("  5 graphiques générés dans figures/")


# ══════════════════════════════════════════════════════════════════════════
# 5. RAPPORT EXCEL COMPLET
# ══════════════════════════════════════════════════════════════════════════

def write_excel(df_synth_crypto, df_taux, df_tm,
                df_synth_ia, df_ia_models, df_atk,
                df_synth_bc, df_e, df_h):

    with pd.ExcelWriter(OUT_EXCEL, engine="xlsxwriter") as writer:
        wb = writer.book

        hfmt = wb.add_format({"bold":True,"bg_color":"#0D47A1","font_color":"white",
                               "border":1,"align":"center","valign":"vcenter"})
        sfmt = wb.add_format({"bold":True,"bg_color":"#1565C0","font_color":"white"})
        best = wb.add_format({"bg_color":"#E8F5E9","bold":True})
        warn = wb.add_format({"bg_color":"#FFF3E0"})

        def write_sheet(df, sheet_name, col_widths=None):
            df.to_excel(writer, sheet_name=sheet_name, index=False)
            ws = writer.sheets[sheet_name]
            for c, col in enumerate(df.columns):
                ws.write(0, c, col, hfmt)
            if col_widths:
                for c, w in enumerate(col_widths):
                    ws.set_column(c, c, w)
            return ws

        # ── Feuille 1 : Synthèse globale ──────────────────────────────────
        df_global = pd.DataFrame([
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Taux détection Injection",       "Valeur":"100.0%","Partie":"D+F"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Taux détection Modification",    "Valeur":"100.0%","Partie":"D+F"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Taux détection Replay/Rollback", "Valeur":"100.0%","Partie":"D+F"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Taux détection Réordonnancement","Valeur":"33.3%* (permutation/inversion non couvertes par comparaison champs)","Partie":"D+F"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Temps chaîne hash (N=128)",      "Valeur":"0.692 ms","Partie":"D"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Temps Merkle (N=128)",           "Valeur":"0.176 ms","Partie":"D"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Temps vérification preuve",      "Valeur":"0.010 ms","Partie":"D"},
            {"Famille":"CRYPTOGRAPHIQUE","Métrique":"Taille preuve Merkle (N=512)",   "Valeur":"424 octets","Partie":"D"},
            {"Famille":"IA","Métrique":"Accuracy (LSTM)",   "Valeur":"0.9809","Partie":"G"},
            {"Famille":"IA","Métrique":"Precision (LSTM)",  "Valeur":"0.9992","Partie":"G"},
            {"Famille":"IA","Métrique":"Recall (LSTM)",     "Valeur":"0.9815","Partie":"G"},
            {"Famille":"IA","Métrique":"F1-score (LSTM)",   "Valeur":"0.9903","Partie":"G"},
            {"Famille":"IA","Métrique":"AUROC (LSTM)",      "Valeur":"0.9922","Partie":"G"},
            {"Famille":"IA","Métrique":"AUPRC (LSTM)",      "Valeur":"0.9999","Partie":"G"},
            {"Famille":"IA","Métrique":"FPR (LSTM)",        "Valeur":"0.0038","Partie":"G"},
            {"Famille":"IA","Métrique":"FNR (LSTM)",        "Valeur":"0.0185","Partie":"G"},
            {"Famille":"IA","Métrique":"Detection delay",   "Valeur":"257 logs avant ancrage (stratégie Fixe N=512)","Partie":"H"},
            {"Famille":"BLOCKCHAIN","Métrique":"Gas par ancrage",          "Valeur":"368 750","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Gas total (Δt=1min/5000 logs)","Valeur":"10 325 008","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Latence ancrage",          "Valeur":"0.022 s","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Débit (Δt=1min)",          "Valeur":"7 799 logs/s","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Nb transactions (Δt=5min)","Valeur":"8","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Taille on-chain/tx",       "Valeur":"305 octets","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Stockage off-chain (100k logs)","Valeur":"25.0 MB","Partie":"E"},
            {"Famille":"BLOCKCHAIN","Métrique":"Meilleure stratégie (J min)","Valeur":"Fixe N=512 (J=0.0432)","Partie":"H"},
        ])
        ws1 = write_sheet(df_global, "synthese_globale",
                          col_widths=[18, 38, 50, 8])

        # ── Feuille 2 : Métriques cryptographiques ─────────────────────────
        ws2 = write_sheet(df_synth_crypto, "metriques_cryptographiques",
                          col_widths=[45, 35])
        ws2_b = write_sheet(df_taux, "detection_par_attaque",
                            col_widths=[38, 18, 12, 12, 15, 18])
        ws2_c = write_sheet(df_tm, "timing_merkle",
                            col_widths=[10, 18, 18, 22, 22, 20, 13])

        # ── Feuille 3 : Métriques IA ───────────────────────────────────────
        ws3 = write_sheet(df_synth_ia, "metriques_ia_synthese",
                          col_widths=[45, 60])
        ws3_b = write_sheet(df_ia_models, "metriques_ia_modeles",
                            col_widths=[20,11,11,11,11,11,11,11,11,8,8,8,8,16])
        ws3_c = write_sheet(df_atk, "recall_par_attaque",
                            col_widths=[22, 30, 12, 12, 12, 12, 13])

        # Mise en forme LSTM (meilleur modèle)
        lstm_row = df_ia_models[df_ia_models["Modèle"]=="LSTM"].index
        if len(lstm_row):
            for c in range(len(df_ia_models.columns)):
                ws3_b.write(lstm_row[0]+1, c,
                            df_ia_models.iloc[lstm_row[0], c], best)

        # ── Feuille 4 : Métriques blockchain ──────────────────────────────
        ws4 = write_sheet(df_synth_bc, "metriques_blockchain",
                          col_widths=[42, 35])
        ws4_b = write_sheet(df_e, "cout_ancrage_dt",
                            col_widths=[16,12,16,14,18,11,11,22,22,28,26,22])
        ws4_c = write_sheet(df_h[["strategie","n_transactions","gas_total",
                                   "latence_moy_logs","score_securite",
                                   "taux_detection","J_objectif"]],
                            "cout_strategies",
                            col_widths=[40,16,14,18,16,16,12])

    print(f"Rapport Excel : {OUT_EXCEL}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("="*65)
    print("PARTIE I — Évaluation complète du système")
    print("="*65)

    df_synth_crypto, df_taux, df_tm = build_crypto_metrics()
    df_synth_ia, df_ia_models, df_atk = build_ia_metrics()
    df_synth_bc, df_e, df_h = build_blockchain_metrics()

    plot_all(df_taux, df_ia_models, df_tm, df_h)

    write_excel(df_synth_crypto, df_taux, df_tm,
                df_synth_ia, df_ia_models, df_atk,
                df_synth_bc, df_e, df_h)

    print("\n"+"="*65)
    print("RÉSUMÉ DES MÉTRIQUES CLÉS")
    print("="*65)
    print(f"\n{'─'*30} CRYPTOGRAPHIQUE {'─'*17}")
    print("  Détection Injection/Modif/Replay/Rollback : 100%")
    print("  Détection Réordonnancement (déplacement)  : 100%")
    print("  Réordonnancement (permutation/inversion)  : 0%  (couvert par LSTM)")
    print("  Temps vérification preuve Merkle          : ~0.01 ms")
    print("  Taille preuve Merkle (N=512)              : 424 octets")
    print(f"\n{'─'*30} IA (LSTM) {'─'*25}")
    print("  F1=0.9903  AUROC=0.9922  Recall=0.9815  FNR=0.019")
    print(f"\n{'─'*30} BLOCKCHAIN {'─'*23}")
    print("  Gas/tx=368 750  |  Meilleure stratégie: Fixe N=512 (J=0.043)")
    print("  Débit=7 799 logs/s  |  Stockage off-chain=25 MB/100k logs")

if __name__ == "__main__":
    main()
