from django.shortcuts import render
from django.core import serializers
import time
from django.http import HttpResponse,JsonResponse
import warnings
from .models import *
from testing1 import *
import os
from django.contrib.sessions.models import Session
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
res = ""
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from features import single,main2,main
import pandas as pd
import pickle

def startpage(request):
    return render(request,"login.html",{})

def transfer(request):
    return render(request,"transfer.html",{})

def login(request):
    return render(request,"login.html",{})

def index(request):
    return render(request,"index.html",{})

def trainadmin(request):
    global res
    res = ""
    return render(request,"admin_train.html",{"res": res})

def transferingfile(request):
    tdata=request.POST.get("url")
##    tdata = tdata.replace("/","")
    res = predict(tdata)
    print("Result : ",)
    resv = res
    res=['Normal','Phishing']
    print(res[int(resv)])
    print("Result : ",res[int(resv)])
    print(res[int(resv)])
    return render(request,"transfer.html",{"res": res[int(resv)], "r": "Result for "+str(tdata), "pred": "Predicted: "})

def adminhome(request):
    return render(request,"admin_new_home.html",{})

def about(request):
    return render(request,'about.html',{})

def contact(request):
    return render(request,'contact.html',{})

def newregister(request):
    return render(request,'register.html',{})

def contactmess(request):
    name=request.POST.get("name")
    email=request.POST.get("email")
    phone=request.POST.get("phone")
    mess=request.POST.get("mess")
    print("Name: ",name)
    print("Email: ",email)
    print("Phone: ",phone)
    print("Message: ",mess)
    try:
        ob=contactdet(name=name,email=email,phone=phone,mess=mess).save()
        return HttpResponse("<script>alert('Your Enquiry is send');window.location.href='/contact/'</script>")
    except:
        return HttpResponse("<script>alert('Failed to send your message');window.location.href='/contact/'</script>")


def deppred(request):
    global res
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
    res = "Accuracy: "+str(ac)
    return render(request,"admin_train.html",{"res": res})

def registeration(request):
    name=request.POST.get("name")
    email=request.POST.get("email")
    mob=request.POST.get("mobile")
    username=request.POST.get("username")
    password=request.POST.get("password")
    print("Name: ",name)
    n1=str(name)
    print("Email: ",email)
    print("Username: ",username)
    print("Password: ",password)
    
    
    try:
        if username=="admin":
            return HttpResponse("<script>alert('You cannot use admin as username.');window.location.href='/login/'</script>")
        ob=register(name=name,email=email,mob=mob,username=username,password=password).save()
        return HttpResponse("<script>alert('SUCCESSFULLY REGISTERED');window.location.href='/login/'</script>")
    except Exception as ex:
        print("Exception",str(ex))
        return HttpResponse("<script>alert('FAILED TO REGISTER. USERNAME ALREADY TAKEN');window.location.href='/login/'</script>")


def userApprove(request):
    ob=register.objects.raw("select * from App_register where status=0 order by id desc limit 10;")
    return render(request,'admin_user_approval.html',{"data":ob})

def regUsers(request):
    ob=register.objects.raw("select * from App_register where status=1 order by id desc limit 10;")
    return render(request,'admin_registered.html',{"data":ob})


def approve(request):
    name=request.POST.get("name")
    email=request.POST.get("email")
    mob=request.POST.get("mob")
    username=request.POST.get("username")
    obj=register.objects.get(username=username)
    obj.status=1
    obj.save()

    return HttpResponse("<script>alert('User Approved');window.location.href='/userApprove/'</script>")


def check(request):
    email=request.POST.get("email")
    password=request.POST.get("password")
    print ("Email: ",email)
    print("password",password)
    if email=="admin" and password=="admin":
        return HttpResponse("<script>alert('Success. Welcome Admin');window.location.href='/adminhome/'</script>")
    else:
        try:
            obj=register.objects.get(username=email,password=password)
            if obj.status==1:
                request.session["email"]=email
                return HttpResponse("<script>alert('Success. Welcome "+obj.name+"');window.location.href='/index/'</script>")   
            else:
                return HttpResponse("<script>alert('Please be Patient. Admin is Verifying');window.location.href='/login/'</script>")
            
                 
        except Exception as ex:
            print(ex)
            return HttpResponse("<script>alert('Try Again');window.location.href='/login/'</script>")
