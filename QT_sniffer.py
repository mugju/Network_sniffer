# coding: utf-8
 
import sys
from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import uic
from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSlot

from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from HTTP_sniffer_v import *
from ICMP_sniffer import *
from DNS_sniffer import *

#아 한글 안쳐지는거 개빡치네



#UI파일 연결
#단, UI파일은 Python 코드 파일과 같은 디렉토리에 위치해야한다.
form_class = uic.loadUiType("ui.ui")[0]


#화면을 띄우는데 사용되는 Class 선언
class WindowClass(QMainWindow, form_class) :
    def __init__(self) :
        super().__init__()
        self.setupUi(self)


        # 버튼에 기능을 연결하는 코드
        self.HTTP_.clicked.connect(self.HTTP) #HTTP스니
        self.ICMP_.clicked.connect(self.ICMP) #ICMP스니
        self.DNS_.clicked.connect(self.DNS) #ICMP스니
        
        self.Clear.clicked.connect(self.clear) #창 비움  
 





	##여기부터 우리 코드 시작
    def HTTP (self):
        HTTP_sni() #스니핑
        
        with open('http_data.txt', 'r') as MyFile:
            MyString = MyFile.read()
            if self.checkBox.isChecked():
                self.textBrowser.append(MyString)
            else : self.textBrowser.setPlainText(MyString)
        MyFile.close()
         
    def ICMP (self):
        
        ICMP_sniff()
        with open('icmp_data.txt', 'r') as MyFile_1:
            MyString_1 = MyFile_1.read()
            if self.checkBox.isChecked():
                self.textBrowser.append(MyString_1)		
            else : self.textBrowser.setPlainText(MyString_1)
        MyFile_1.close()
        
 
    def DNS (self):
        
        DNS_sniff()
        with open('DNS.txt', 'r') as MyFile_2:
            MyString_2 = MyFile_2.read()
            if self.checkBox.isChecked():
                self.textBrowser.append(MyString_2)		
            else : self.textBrowser.setPlainText(MyString_2)
        MyFile_2.close()
            
    def clear (self):
        self.textBrowser.clear()







if __name__ == "__main__" :

    
    #QApplication : 프로그램을 실행시켜주는 클래스
    app = QApplication(sys.argv)

    #WindowClass의 인스턴스 생성
    myWindow = WindowClass()

    #프로그램 화면을 보여주는 코드
    myWindow.show()

    #프로그램을 이벤트루프로 진입시키는(프로그램을 작동시키는) 코드자자이니니니
    app.exec_()
