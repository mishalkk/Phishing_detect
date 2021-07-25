import pandas as pd 

df1=pd.read_csv('DeepPhishURLS.csv')
df2=pd.read_csv('ThreatActor1URLS_p.csv')
df3=pd.read_csv('urldata.csv')

print(df1.columns)
print(df2.columns)
print(df3.columns)

print(len(df3))
df3=df3[df3.label=='good']



df3['label']=[0 for i in df3.url]


df3=df3[['url','label']][:2000]
print(df3.head())
print(len(df3))

def rem(x):
    x=x[7:]
    #print(x)
    return x

df1['url']=[i for i in df1.URL]
df1['label']=[1 for i in df1.url]
df1=df1[['url','label']]
df1.url=df1.url.apply(rem)
print(df1.head())
print(len(df1))





df2['url']=[i for i in df2.URL]
df2['label']=[1 for i in df2.url]
df2=df2[['url','label']]
df2.url=df2.url.apply(rem)
print(df2.head())
print(len(df2))

from features import main

dfy=pd.concat([df1, df2])['url'][:1000]
df3=df3['url']

df3.to_csv('nophish.csv',index=False,header=False)
dfy.to_csv('phish.csv',index=False,header=False)

# main('nophish.csv','result1.csv',0)
#main('phish.csv','result2.csv',1)

dfn=pd.read_csv('result1.csv')
dfy=pd.read_csv('result2.csv')

dtypes1=list(dict(dfn.dtypes).keys())
dtypes2=list(dict(dfn.dtypes).values())

print(dtypes2[0])
print(type(dtypes2[0]))
drop_list=[]
c_list=[]
for i in range(len(dtypes2)):
    if str(dtypes2[i])!='int64':
        print(str(dtypes1[i]))

        if str(dtypes2[i])=='bool':
            c_list.append(dtypes1[i])
        else: 
            drop_list.append(dtypes1[i])
       

dfn=dfn.drop(drop_list,axis=1)
dfy=dfy.drop(drop_list,axis=1)

df=pd.concat([dfy, dfn])

for i in range(len(c_list)):
    df[c_list[i]]=[int(j) for j in df[c_list[i]]]

print(df.ip_exist.head())

corr=df.corr()
cor_target = abs(corr["phishing"])
#Selecting highly correlated features
relevant_features = dict(cor_target[cor_target>0.3])
print(relevant_features)

import pickle

f=open('r_features.pkl','wb')
pickle.dump(relevant_features,f)
f.close()

r_f=list(relevant_features.keys())
df=df[r_f]

print(df.head())

X=df.drop(['phishing'],axis=1)
y=df['phishing']


from sklearn.ensemble import RandomForestClassifier
clf = RandomForestClassifier(max_depth=2, random_state=0)


from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y,random_state=1)
X_train=X_train.to_numpy()
X_test=X_test.to_numpy()

print(X_train[0])
#n/0

clf.fit(X_train,y_train)


f=open('clrf.pkl','wb')
pickle.dump(clf,f)
f.close()

#print(clfs[0].predict(X_test))

feat=[]
from sklearn.metrics import accuracy_score
pred=clf.predict(X_train)
ac=accuracy_score(pred,y_train)
print("Accuracy: ",ac)
feat.append(pred)



f=open('accuracy.pkl','wb')
pickle.dump(ac,f)
f.close()

























