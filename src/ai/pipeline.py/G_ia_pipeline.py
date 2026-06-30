"""
G_ia_pipeline.py  —  Partie G : Détection IA des falsifications de logs BGL
"""
import os, sys, warnings, pickle, time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC, OneClassSVM
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    precision_recall_curve, roc_curve,
    confusion_matrix, f1_score,
    precision_score, recall_score, accuracy_score,
)
warnings.filterwarnings("ignore")

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
FALSIFIED_XL = os.path.join(SCRIPT_DIR, "falsification_BGL.xlsx")
OUT_EXCEL    = os.path.join(SCRIPT_DIR, "ai_results.xlsx")
FIG_DIR      = os.path.join(SCRIPT_DIR, "figures")
MDL_DIR      = os.path.join(SCRIPT_DIR, "models")
os.makedirs(FIG_DIR, exist_ok=True)
os.makedirs(MDL_DIR, exist_ok=True)
SEED = 42
np.random.seed(SEED)
LIGHT_ATTACKS = {0.001, 0.005}
HEAVY_ATTACKS = {0.01, 0.05, 0.10}
NUM_FEATURES  = ["delta_t","n_critical_window","position_norm",
                 "severity_ratio","raw_log_len","template_len","template_num_count"]

# ── 1. Chargement ──────────────────────────────────────────────────────────
def load_data():
    print("Chargement des données...")
    df = pd.read_excel(FALSIFIED_XL, sheet_name="logs_falsifies")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("seq_no").reset_index(drop=True)
    df["y"] = (df["log_label"] != "clean").astype(int)
    print(f"  Total : {len(df)}  clean={( df['y']==0).sum()}  tampered={(df['y']==1).sum()}")
    return df

def build_features(df):
    df = df.copy().sort_values("timestamp").reset_index(drop=True)
    df["delta_t"]            = df["timestamp"].diff().dt.total_seconds().fillna(0).clip(0,3600)
    df["is_critical"]        = (df["severity"]=="FATAL").astype(int)
    df["n_critical_window"]  = df["is_critical"].rolling(10, min_periods=1).sum()
    df["position_norm"]      = np.arange(len(df)) / max(len(df)-1,1)
    df["severity_ratio"]     = df["is_critical"].rolling(20, min_periods=1).mean()
    df["raw_log_len"]        = df["raw_log"].astype(str).str.len()
    df["template_len"]       = df["event_template"].astype(str).str.len()
    df["template_num_count"] = df["event_template"].astype(str).str.count(r"\d")
    return df

def split_data(df):
    clean_mask = df["log_label"]=="clean"
    light_mask = df["severity_level"].isin(LIGHT_ATTACKS)
    heavy_mask = df["severity_level"].isin(HEAVY_ATTACKS)

    ci = df[clean_mask].index.tolist(); np.random.shuffle(ci); n=len(ci)
    c_tr, c_v, c_te = ci[:int(.70*n)], ci[int(.70*n):int(.85*n)], ci[int(.85*n):]
    li = df[light_mask&~clean_mask].index.tolist(); np.random.shuffle(li); nl=len(li)
    l_tr, l_v = li[:int(.70*nl)], li[int(.70*nl):]
    hi = df[heavy_mask&~clean_mask].index.tolist()

    dtr = df.loc[sorted(c_tr+l_tr)].reset_index(drop=True)
    dv  = df.loc[sorted(c_v+l_v)].reset_index(drop=True)
    dte = df.loc[sorted(c_te+hi)].reset_index(drop=True)
    print(f"\nSplit — train:{len(dtr)} val:{len(dv)} test:{len(dte)}")
    print(f"  Train tampered={( dtr['y']==1).sum()} | Test tampered={(dte['y']==1).sum()}")
    return dtr, dv, dte

# ── 2. Features ────────────────────────────────────────────────────────────
def fit_tfidf(dtr):
    tv = TfidfVectorizer(max_features=3000, ngram_range=(1,2), sublinear_tf=True, min_df=2)
    tv.fit(dtr["event_template"].astype(str))
    return tv

def get_X(df, tv, sc, fit=False):
    from scipy.sparse import hstack, csr_matrix
    Xt = tv.transform(df["event_template"].astype(str))
    Xn = df[NUM_FEATURES].fillna(0).values.astype(np.float32)
    if fit: sc.fit(Xn)
    return hstack([Xt, csr_matrix(sc.transform(Xn))])

# ── 3. Évaluation ──────────────────────────────────────────────────────────
def evaluate(name, yt, ys, yp, atk=None):
    r = {"model": name,
         "accuracy":  round(accuracy_score(yt,yp),4),
         "precision": round(precision_score(yt,yp,zero_division=0),4),
         "recall":    round(recall_score(yt,yp,zero_division=0),4),
         "f1":        round(f1_score(yt,yp,zero_division=0),4)}
    if ys is not None and len(np.unique(yt))>1:
        r["roc_auc"] = round(roc_auc_score(yt,ys),4)
        r["pr_auc"]  = round(average_precision_score(yt,ys),4)
    else:
        r["roc_auc"] = r["pr_auc"] = None
    print(f"\n{'─'*50}\n  {name}")
    for k,v in r.items():
        if k!="model": print(f"  {k:<12}: {v}")

    safe = name.replace(" ","_").replace("/","_").replace("+","")

    if ys is not None and r["roc_auc"]:
        fpr,tpr,_ = roc_curve(yt,ys)
        plt.figure(figsize=(5,4))
        plt.plot(fpr,tpr,lw=2,label=f"AUC={r['roc_auc']:.3f}")
        plt.plot([0,1],[0,1],"k--",lw=1)
        plt.xlabel("FPR"); plt.ylabel("TPR"); plt.title(f"ROC — {name}")
        plt.legend(); plt.tight_layout()
        plt.savefig(f"{FIG_DIR}/roc_{safe}.png",dpi=120); plt.close()

        pr,rec,_ = precision_recall_curve(yt,ys)
        plt.figure(figsize=(5,4))
        plt.plot(rec,pr,lw=2,label=f"PR-AUC={r['pr_auc']:.3f}")
        plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title(f"PR — {name}")
        plt.legend(); plt.tight_layout()
        plt.savefig(f"{FIG_DIR}/pr_{safe}.png",dpi=120); plt.close()

    cm = confusion_matrix(yt,yp)
    plt.figure(figsize=(4,3))
    plt.imshow(cm,cmap="Blues"); plt.colorbar()
    plt.xticks([0,1],["Prédit\nClean","Prédit\nFalsifié"])
    plt.yticks([0,1],["Réel\nClean","Réel\nFalsifié"])
    for i in range(2):
        for j in range(2):
            plt.text(j,i,str(cm[i,j]),ha="center",va="center",fontsize=12,
                     color="white" if cm[i,j]>cm.max()/2 else "black")
    plt.title(f"CM — {name}"); plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/cm_{safe}.png",dpi=120); plt.close()

    if atk is not None:
        _plot_recall_by_attack(name, safe, yt, yp, atk)
    return r

def _plot_recall_by_attack(name, safe, yt, yp, atk):
    df_tmp = pd.DataFrame({"yt":yt,"yp":yp,"atk":atk})
    attacks = sorted(df_tmp[df_tmp["yt"]==1]["atk"].unique())
    if not attacks: return
    recalls = [recall_score(df_tmp[df_tmp["atk"]==a]["yt"],
                            df_tmp[df_tmp["atk"]==a]["yp"], zero_division=0)
               for a in attacks]
    plt.figure(figsize=(max(8,len(attacks)*0.9),4))
    bars = plt.bar(range(len(attacks)), recalls, color="steelblue")
    plt.xticks(range(len(attacks)),[a.replace("_","\n") for a in attacks],fontsize=7)
    plt.ylim(0,1.15); plt.ylabel("Recall")
    plt.title(f"Recall par type d'attaque — {name}")
    for b,v in zip(bars,recalls):
        plt.text(b.get_x()+b.get_width()/2, v+0.02, f"{v:.2f}",
                 ha="center",va="bottom",fontsize=7)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/recall_by_attack_{safe}.png",dpi=120); plt.close()

# ── 4. Modèles ─────────────────────────────────────────────────────────────
def run_lr(Xtr,ytr,Xte,yte,dte):
    print("\n[1/5] TF-IDF + Logistic Regression")
    t0=time.time()
    clf=LogisticRegression(max_iter=1000,C=1.0,class_weight="balanced",
                            solver="lbfgs",random_state=SEED)
    clf.fit(Xtr,ytr)
    ys=clf.predict_proba(Xte)[:,1]; yp=clf.predict(Xte)
    pickle.dump(clf,open(f"{MDL_DIR}/lr.pkl","wb"))
    r=evaluate("TF-IDF + LR",yte,ys,yp,atk=dte["attack_type"].values)
    r["train_time_s"]=round(time.time()-t0,2); return r, yp

def run_svm(Xtr,ytr,Xte,yte,dte):
    print("\n[2/5] TF-IDF + SVM")
    t0=time.time()
    MAX=8000
    if Xtr.shape[0]>MAX:
        idx=np.random.choice(Xtr.shape[0],MAX,replace=False)
        Xtr=Xtr[idx]; ytr=ytr[idx]
    clf=SVC(kernel="rbf",C=1.0,probability=True,class_weight="balanced",random_state=SEED)
    clf.fit(Xtr,ytr)
    ys=clf.predict_proba(Xte)[:,1]; yp=clf.predict(Xte)
    pickle.dump(clf,open(f"{MDL_DIR}/svm.pkl","wb"))
    r=evaluate("TF-IDF + SVM",yte,ys,yp,atk=dte["attack_type"].values)
    r["train_time_s"]=round(time.time()-t0,2); return r, yp

def run_iforest(Xclean,Xte,yte,dte):
    print("\n[3/5] Isolation Forest")
    t0=time.time()
    clf=IsolationForest(n_estimators=200,contamination=0.15,random_state=SEED,n_jobs=-1)
    clf.fit(Xclean)
    ys=-clf.score_samples(Xte); yp=(clf.predict(Xte)==-1).astype(int)
    pickle.dump(clf,open(f"{MDL_DIR}/iforest.pkl","wb"))
    r=evaluate("Isolation Forest",yte,ys,yp,atk=dte["attack_type"].values)
    r["train_time_s"]=round(time.time()-t0,2); return r, yp

def run_ocsvm(Xclean,Xte,yte,dte):
    print("\n[4/5] One-Class SVM")
    MAX=4000
    Xc=Xclean
    if Xc.shape[0]>MAX:
        idx=np.random.choice(Xc.shape[0],MAX,replace=False); Xc=Xc[idx]
    t0=time.time()
    clf=OneClassSVM(kernel="rbf",nu=0.15,gamma="scale")
    clf.fit(Xc)
    ys=-clf.score_samples(Xte); yp=(clf.predict(Xte)==-1).astype(int)
    pickle.dump(clf,open(f"{MDL_DIR}/ocsvm.pkl","wb"))
    r=evaluate("One-Class SVM",yte,ys,yp,atk=dte["attack_type"].values)
    r["train_time_s"]=round(time.time()-t0,2); return r, yp

# ── LSTM minimal NumPy ──────────────────────────────────────────────────────
class SimpleLSTM:
    def __init__(self,V,E=32,H=64,seed=42):
        np.random.seed(seed); s=0.1
        self.V=V; self.E_dim=E; self.H=H
        self.Emb=np.random.randn(V,E)*s
        d=E+H
        self.Wf=np.random.randn(H,d)*s; self.bf=np.zeros(H)
        self.Wi=np.random.randn(H,d)*s; self.bi=np.zeros(H)
        self.Wc=np.random.randn(H,d)*s; self.bc=np.zeros(H)
        self.Wo=np.random.randn(H,d)*s; self.bo=np.zeros(H)
        self.Wy=np.random.randn(1,H)*s; self.by=np.zeros(1)

    def _sig(self,x): return 1/(1+np.exp(-np.clip(x,-10,10)))
    def _tanh(self,x): return np.tanh(np.clip(x,-10,10))

    def _forward(self,seq):
        h=np.zeros(self.H); c=np.zeros(self.H)
        for idx in seq:
            idx=min(idx,self.V-1); x=self.Emb[idx]; xh=np.concatenate([x,h])
            f=self._sig(self.Wf@xh+self.bf); i=self._sig(self.Wi@xh+self.bi)
            c_=self._tanh(self.Wc@xh+self.bc); o=self._sig(self.Wo@xh+self.bo)
            c=f*c+i*c_; h=o*self._tanh(c)
        return h

    def predict_proba(self,seq):
        h=self._forward(seq); return float(self._sig((self.Wy@h).flatten()[0]+self.by[0]))

    def fit(self,seqs,labels,epochs=6,lr=0.005,bs=128):
        n=len(seqs)
        for ep in range(epochs):
            idx=np.random.permutation(n); loss=0.0
            for st in range(0,n,bs):
                for i in idx[st:st+bs]:
                    p=self.predict_proba(seqs[i]); y=labels[i]
                    loss+=-(y*np.log(p+1e-9)+(1-y)*np.log(1-p+1e-9))
                    g=p-y; h=self._forward(seqs[i])
                    self.Wy-=lr*g*h.reshape(1,-1); self.by-=lr*np.array([g])
                    for tok in seqs[i]:
                        tok=min(tok,self.V-1); self.Emb[tok]-=lr*g*0.01
            if ep==0 or (ep+1)%2==0:
                print(f"    Epoch {ep+1}/{epochs}  loss={loss/n:.4f}")

def _make_seqs(df, window=20):
    df=df.sort_values("seq_no").reset_index(drop=True)
    eids=df["event_id"].astype(str).tolist()
    ys=df["y"].tolist(); atks=df["attack_type"].tolist()
    seqs,labs,atkout=[],[],[]
    for i in range(0,len(df)-window+1,window//2):
        seqs.append(eids[i:i+window]); labs.append(int(any(ys[i:i+window])))
        chunk=[a for a in atks[i:i+window] if str(a) not in ("","nan")]
        atkout.append(chunk[0] if chunk else "none")
    return seqs,labs,atkout

def run_lstm(dtr,dte):
    print("\n[5/5] LSTM sur séquences d'EventId")
    str_,ytr_,_=_make_seqs(dtr); ste_,yte_,atke_=_make_seqs(dte)
    vocab={}
    for s in str_:
        for t in s:
            if t not in vocab: vocab[t]=len(vocab)+1
    def enc(s): return [vocab.get(t,0) for t in s]
    Xtr=[enc(s) for s in str_]; Xte=[enc(s) for s in ste_]
    # équilibre
    pi=[i for i,y in enumerate(ytr_) if y==1]
    ni=[i for i,y in enumerate(ytr_) if y==0]
    if pi and len(ni)>len(pi): ni=list(np.random.choice(ni,len(pi)*2,replace=False))
    bi=sorted(pi+ni); Xb=[Xtr[i] for i in bi]; yb=[ytr_[i] for i in bi]
    t0=time.time()
    model=SimpleLSTM(V=len(vocab)+1,E=32,H=64)
    model.fit(Xb,yb,epochs=6,lr=0.005)
    elapsed=time.time()-t0
    ys_=np.array([model.predict_proba(s) for s in Xte])
    yp_=(ys_>=0.5).astype(int); yte_=np.array(yte_); atke_=np.array(atke_)
    pickle.dump({"model":model,"vocab":vocab},open(f"{MDL_DIR}/lstm.pkl","wb"))
    r=evaluate("LSTM",np.array(yte_),ys_,yp_,atk=atke_)
    r["train_time_s"]=round(elapsed,2)
    # aligner sur df_test (fenêtrage -> taille peut différer)
    if len(yp_)>=len(dte): yp_full=yp_[:len(dte)]
    else: yp_full=np.concatenate([yp_,np.zeros(len(dte)-len(yp_),dtype=int)])
    return r, yp_full

# ── 5. Graphique comparatif ─────────────────────────────────────────────────
def plot_comparison(results):
    models=[r["model"] for r in results]
    metrics=[("f1","F1"),("roc_auc","ROC-AUC"),("pr_auc","PR-AUC"),
             ("precision","Precision"),("recall","Recall")]
    colors=["#2196F3","#4CAF50","#FF9800","#9C27B0","#F44336"]
    x=np.arange(len(models)); w=0.15
    fig,ax=plt.subplots(figsize=(14,6))
    for i,(m,lab) in enumerate(metrics):
        vals=[r.get(m) or 0 for r in results]
        ax.bar(x+i*w,vals,w,label=lab,color=colors[i],alpha=0.85)
        for j,v in enumerate(vals):
            ax.text(x[j]+i*w,v+0.01,f"{v:.2f}",ha="center",va="bottom",fontsize=6)
    ax.set_xticks(x+w*2); ax.set_xticklabels(models,fontsize=9)
    ax.set_ylim(0,1.15); ax.set_ylabel("Score")
    ax.set_title("Comparaison complète des modèles IA — Partie G")
    ax.legend(loc="upper right",fontsize=9)
    ax.axhline(0.5,color="gray",linestyle="--",lw=0.7)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/comparison_all_models.png",dpi=150); plt.close()
    print("Graphique comparatif : figures/comparison_all_models.png")

# ── 6. Rapport Excel ────────────────────────────────────────────────────────
def write_report(results, dte, preds_by_model):
    print(f"\nRapport Excel : {OUT_EXCEL}")
    with pd.ExcelWriter(OUT_EXCEL, engine="xlsxwriter") as writer:
        wb=writer.book
        # Feuille 1 : comparaison
        pd.DataFrame(results).to_excel(writer,sheet_name="comparaison_modeles",index=False)
        ws=writer.sheets["comparaison_modeles"]
        hfmt=wb.add_format({"bold":True,"bg_color":"#1565C0","font_color":"white"})
        for c,n in enumerate(pd.DataFrame(results).columns): ws.write(0,c,n,hfmt)
        ws.set_column(0,0,28); ws.set_column(1,20,13)

        # Feuille 2 : métriques par attaque
        rows=[]
        for mname,yp in preds_by_model.items():
            for atk in dte["attack_type"].unique():
                mask=dte["attack_type"].values==atk
                yt=dte["y"].values[mask]; ypm=yp[mask]
                if len(yt)==0 or len(np.unique(yt))==0: continue
                rows.append({"model":mname,"attack_type":atk,"n_logs":int(mask.sum()),
                             "precision":round(precision_score(yt,ypm,zero_division=0),4),
                             "recall":round(recall_score(yt,ypm,zero_division=0),4),
                             "f1":round(f1_score(yt,ypm,zero_division=0),4),
                             "n_detected":int(ypm.sum())})
        pd.DataFrame(rows).to_excel(writer,sheet_name="metriques_par_attaque",index=False)

        # Feuille 3 : prédictions test
        dfp=dte[["log_id","seq_no","log_label","attack_type","severity_level","y"]].copy()
        for mn,yp in preds_by_model.items():
            dfp[f"pred_{mn[:15].replace(' ','_')}"] = yp
        dfp.to_excel(writer,sheet_name="predictions_test",index=False)

        # Feuille 4 : synthèse
        best=max(results,key=lambda r:r.get("f1") or 0)
        pd.DataFrame([
            {"Indicateur":"Meilleur modèle (F1)","Valeur":best["model"]},
            {"Indicateur":"Meilleur F1","Valeur":best["f1"]},
            {"Indicateur":"Meilleur ROC-AUC","Valeur":best.get("roc_auc")},
            {"Indicateur":"Logs testés","Valeur":len(dte)},
            {"Indicateur":"Logs falsifiés test","Valeur":int(dte["y"].sum())},
            {"Indicateur":"Types d'attaque","Valeur":dte["attack_type"].nunique()},
            {"Indicateur":"Features","Valeur":"TF-IDF 3000 + 7 numériques"},
            {"Indicateur":"Split","Valeur":"train:clean+léger / test:lourd(1-10%)"},
        ]).to_excel(writer,sheet_name="synthese",index=False)
    print(f"Ecrit : {OUT_EXCEL}")

# ── MAIN ────────────────────────────────────────────────────────────────────
def main():
    print("="*60)
    print("PARTIE G — Détection IA des falsifications BGL")
    print("="*60)

    df=load_data(); df=build_features(df)
    dtr,dv,dte=split_data(df)

    print("\nApprentissage TF-IDF sur train uniquement...")
    tv=fit_tfidf(dtr); sc=StandardScaler(with_mean=False)
    Xtr=get_X(dtr,tv,sc,fit=True)
    Xte=get_X(dte,tv,sc)
    ytr=dtr["y"].values; yte=dte["y"].values
    Xclean=get_X(dtr[dtr["y"]==0],tv,sc)
    pickle.dump(tv,open(f"{MDL_DIR}/tfidf.pkl","wb"))
    pickle.dump(sc,open(f"{MDL_DIR}/scaler.pkl","wb"))

    all_results=[]; preds={}

    r,yp=run_lr(Xtr,ytr,Xte,yte,dte);        all_results.append(r); preds["TF-IDF+LR"]=yp
    r,yp=run_svm(Xtr.copy(),ytr,Xte,yte,dte); all_results.append(r); preds["TF-IDF+SVM"]=yp
    r,yp=run_iforest(Xclean,Xte,yte,dte);    all_results.append(r); preds["IForest"]=yp
    r,yp=run_ocsvm(Xclean,Xte,yte,dte);      all_results.append(r); preds["OCSVM"]=yp
    r,yp=run_lstm(dtr,dte);                   all_results.append(r); preds["LSTM"]=yp

    plot_comparison(all_results)
    write_report(all_results, dte, preds)

    print("\n"+"="*60+"  RÉSUMÉ FINAL  "+"="*60)
    print(f"{'Modèle':<30} {'F1':>6} {'ROC-AUC':>9} {'PR-AUC':>8} {'Temps(s)':>9}")
    print("─"*65)
    for r in all_results:
        print(f"{r['model']:<30} {str(r.get('f1','—')):>6} "
              f"{str(r.get('roc_auc','—')):>9} {str(r.get('pr_auc','—')):>8} "
              f"{str(r.get('train_time_s','—')):>9}")
    best=max(all_results,key=lambda r:r.get("f1") or 0)
    print(f"\nMeilleur modèle : {best['model']}  F1={best['f1']}")

if __name__=="__main__":
    main()
