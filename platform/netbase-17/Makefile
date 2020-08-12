######################################

#Makefile

######################################
#�������&Ԥ����
#ע��:
#	������������shell�ű�һ����eg:$(OBJ)

#��̬��(dynamic lib)
OUTFILE_SO = libnetb.so

#��̬��(static lib)
OUTFILE = libnetb.a

#���Ŀ��(output obj)
OBJ = \
	conn_listener.o\
	thread.o\


	

#�����ľ�̬��(dependent static dll)
LIBS_STATIC = \
	


#�����Ķ�̬��(dependent dynamic dll)
LIBS_SO = \
    -L /usr/local/lib64 -lpthread -lssl -lcrypto -ldl -lrt -lz \
	../lib/libevent.a \
	../lib/libevent_core.a \
	../lib/libevent_extra.a \
	../lib/libevent_openssl.a \
	
	
	#-L../lib -levent_core \
	#-L../lib -levent_extra \
	#-L../lib -levent_openssl \


#����Դ��Ŀ¼
SRC_DIR = \


#����ͷ�ļ�Ŀ¼
#-I	Ԥ����ʱ��ָ������ͷ�ļ���·��dir,
#	����ָ����·��������Ҫ������ͷ�ļ�
#	���Ҳ��������ڱ�׼·��(/usr/include,
#	/usr/lib,����ǰ����Ŀ¼)������
INCLUDE_DIR = \
	-I. \
	-I../include/ \
	-I../../include/ \


	
		
######################################
#��������

CPP = g++
CC = gcc

#������ļ�
INFILE = $(SRC_FILE) $(OBJ) $(LIBS_STATIC) $(LIBS_SO)

#�澯���� 1.�����ڴ��ַ�쳣ʹ�� 2.�����������û��ʹ��
WARNING = -Wall

#�Ż�����ѡ��
#1. -O/-O1	��ͼ���ٴ����С��ִ��ʱ�䣬������ִ����Ҫ��
#�Ѵ�������ʱ����κ��Ż�
#2. -O2 ��-O1�Ļ����ϣ�������һЩ�����������--������ѭ��
#չ�������������ͼĴ������������⣬�������������Ż�
#3. -O3 �������-O2���Ż�֮�⣬�����а���ѭ��չ��������һЩ
#		�봦����������ص��Ż�����
#4. -O4 ��ִ���Ż�
#5. -Os ����-O2������Ż���ͬʱ���ر����Ӵ����С
OPTIMISE = \

#���������Ϣ
DEBUG = -g

#�Ƿ�ʹ�þ�̬��
#STATIC = -static

#
STATIC_LIBS = 

#����ѡ���߳� Ĭ��ȥ����ʼ��lib��ĩβ��.a��so
#libpthread.so librt.so(����ʱ��)
PTHREADLD = -lpthread -lrt

#����ѡ��
#-fPIC�����ڱ���׶Σ����߱�����������λ���޹صĴ��롣�������
#�����У�û�о��Ե�ַ��ȫ��ʹ����Ե�ַ����˴�����Ա����ص�
#�ڴ��е�����λ��
CFLAGS = $(OPTIMISE) $(WARNING) $(DEBUG) $(STATIC) -fPIC -std=c++11
#����ѡ�� ����Ҫ���ӵĿ�
LDFLAGS = $(PTHREADLD) $(STATIC_LIBS)

#1.��׺���� �����������Զ���.cppʶ��ΪԴ�ļ���׺
#.oʶ��Ϊ����ļ���׺
#ע��: ��׺���������κ������ļ���Ҳ����û������
#2.".cpp.o:"�ȼ���"%.o:%.cpp",��:�����е�[.cpp]�ļ��������[.o]�ļ�
#$<:Ϊ�����еĵ�һ�������ļ���;������ģʽΪ��ģʽ�����,��"$<"��ʾ����������Ŀ��İ���ֵ
.cpp.o:
	$(CPP) $(CFLAGS) -c $(INCLUDE_DIR) $<
##############################################
#make
all: exefile_so exefile_a exefile cp
.PHONY:all

##############################################
exefile_so:$(OBJ)
	@echo ============== Build 02==================
	$(CPP) $(CFLAGS) -shared $(INFILE) -o $(OUTFILE_SO)
	
exefile:$(OBJ)
	@echo ============== Build 01==================
	ar -rcs $(CFLAGS) $(OUTFILE) $(INFILE)

exefile:$(OBJ)
	@echo ============== Build ==================
	$(CPP) $(CFLAGS) main.cpp $(INCLUDE_DIR) -L. -lnetb $(LIBS_SO)
cp:
	@echo ============== cp ==================
	#cp $(OUTFILE) ../bin/linux/$(OUTFILE)
	#cp $(OUTFILE_SO) ../bin/linux/$(OUTFILE_SO)
	#cp $(OUTFILE) ../../../lib/linux/$(OUTFILE)
	
.PHONY:clean
clean:
	@echo ============== Clean  ==================
	rm -f $(OBJ) $(OUTFILE) $(OUTFILE_SO) 