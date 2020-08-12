######################################

#Makefile

######################################
#定义变量&预处理
#注意:
#	变量的引用于shell脚本一样，eg:$(OBJ)

#动态库(dynamic lib)
OUTFILE_SO = libnetb.so

#静态库(static lib)
OUTFILE = libnetb.a

#输出目标(output obj)
OBJ = \
	conn_listener.o\
	thread.o\


	

#其他的静态库(dependent static dll)
LIBS_STATIC = \
	


#其他的动态库(dependent dynamic dll)
LIBS_SO = \
    -L /usr/local/lib64 -lpthread -lssl -lcrypto -ldl -lrt -lz \
	../lib/libevent.a \
	../lib/libevent_core.a \
	../lib/libevent_extra.a \
	../lib/libevent_openssl.a \
	
	
	#-L../lib -levent_core \
	#-L../lib -levent_extra \
	#-L../lib -levent_openssl \


#其他源码目录
SRC_DIR = \


#其他头文件目录
#-I	预处理时，指定搜索头文件的路径dir,
#	现在指定的路径下搜索要包含的头文件
#	若找不到，则在标准路径(/usr/include,
#	/usr/lib,及当前工作目录)上搜索
INCLUDE_DIR = \
	-I. \
	-I../include/ \
	-I../../include/ \


	
		
######################################
#编译属性

CPP = g++
CC = gcc

#输入的文件
INFILE = $(SRC_FILE) $(OBJ) $(LIBS_STATIC) $(LIBS_SO)

#告警开关 1.开启内存地址异常使用 2.定义变量但是没有使用
WARNING = -Wall

#优化程序选项
#1. -O/-O1	试图减少代码大小和执行时间，但并不执行需要花
#费大量编译时间的任何优化
#2. -O2 在-O1的基础上，还进行一些额外调整工作--除不做循环
#展开、函数内联和寄存器重新命名外，几乎进行所有优化
#3. -O3 除了完成-O2的优化之外，还进行包括循环展开和其他一些
#		与处理器特性相关的优化工作
#4. -O4 不执行优化
#5. -Os 具有-O2级别的优化，同时不特别增加代码大小
OPTIMISE = \

#加入调试信息
DEBUG = -g

#是否使用静态库
#STATIC = -static

#
STATIC_LIBS = 

#连接选项线程 默认去除开始的lib和末尾的.a或。so
#libpthread.so librt.so(运行时库)
PTHREADLD = -lpthread -lrt

#编译选项
#-fPIC作用于编译阶段，告诉编译器产生与位置无关的代码。则产生的
#代码中，没有绝对地址，全部使用相对地址，因此代码可以被加载到
#内存中的任意位置
CFLAGS = $(OPTIMISE) $(WARNING) $(DEBUG) $(STATIC) -fPIC -std=c++11
#连接选项 添加要连接的库
LDFLAGS = $(PTHREADLD) $(STATIC_LIBS)

#1.后缀规则 编译器将会自动将.cpp识别为源文件后缀
#.o识别为输出文件后缀
#注意: 后缀规则不允许任何依赖文件，也不能没有命令
#2.".cpp.o:"等价于"%.o:%.cpp",即:把所有的[.cpp]文件都编译成[.o]文件
#$<:为规则中的第一个相依文件名;若依赖模式为以模式定义的,则"$<"表示了所有依赖目标的挨个值
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
