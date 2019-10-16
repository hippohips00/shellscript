alias ls=ls
CF=`hostname`"_"`date +%F_%T`.txt

echo > $CF 2>&1

echo "계정 관리" 
echo "계정 관리" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "01. root 계정 원격 접속 제한" >> $CF 2>&1
#목적 : 비인가자의 root 계정 접근 시도를 차단
#위협 : root계정 탈취시 정보 유출, 파일 디렉터리 변조등의 다양한 사고 발생
#tty : 리눅스 콘손 또는 터미널
#/etc/securetty` : Telnet접근시 root접근 제한 설정파일

if [ -z "`grep -v tty\? /etc/securetty`" ]
	then
		echo " [안전]" >> $CF 2>&1
	else
		echo " [취약]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "02. 패스워드 복잡성 설정" >> $CF 2>&1
#목적 : 패스워드 복잡성이 설정되어 무작위 공격, 사전 대입공격 방지
#위협 : 패스워드 패턴이 단순하면 무작위 공격, 사전 대입공격에 의해 계정 탈취가 가능

echo " 알고리즘 :   `authconfig --test | grep hashing | awk '{print $5}'`" >> $CF 2>&1
echo " 최대 사용 기간  :   `cat /etc/login.defs | grep PASS_MAX_DAYS | awk '{print $2}' | sed '1d'`일" >> $CF 2>&1
echo " 최소 사용 시간 :   `cat /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}' | sed '1d'`일" >> $CF 2>&1
echo " 최소 길이 :   `cat /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}' | sed '1d'`글자" >> $CF 2>&1
echo " 기간 만료 경고 기간(일) :   `cat /etc/login.defs | grep PASS_WARN_AGE | awk '{print $2}' | sed '1d'`일" >> $CF 2>&1

echo >> $CF 2>&1

#===============================================

echo "03. 계정 잠금 (임계값) 설정" >> $CF 2>&1
#목적 : 비인가자의 로그인 공격 차단
#위협 : 로그인 실패 횟수 제한을 두지 않으면 무작위 공격 또는 사전 대입 공격이 가능

TI=`grep deny= /etc/pam.d/password-auth | awk '{print $5}' | awk -F = '{print $2}'`

if [ "`grep deny= /etc/pam.d/password-auth`" ]
	then
		echo " [안전]" >> $CF 2>&1
	else
		echo " [취약]" >> $CF 2>&1
fi

echo >> $CF 2>&1

#===============================================

echo "04. 패스워드 파일 보호" >> $CF 2>&1
#목적 : 사용자 정보가 암호화 되어있는지 확인
#위협 : 중요 정보가 평문으로 저장될 시 노출의 위험이 있음
# etc/passwd 파일 내 두번째 필드가 x표시(암호화 여부)인지 확인

if test `cat /etc/passwd | grep "root" | awk -F: '{print $2}' | sed -n '1p'` == x 
	then
		if test -r /etc/shadow
			then
				echo " [안전]" >> $CF 2>&1
			else
				echo " [취약]" >> $CF 2>&1
		fi	
else
	echo " [취약]" >> $CF 2>&1
fi

echo >> $CF 2>&1

#===============================================

echo " 04-1. /etc/passwd" >> $CF 2>&1

PP=`ls -l /etc/passwd | awk {'print $1'}`
PO=`ls -l /etc/passwd | awk {'print $3'}`
PG=`ls -l /etc/passwd | awk {'print $4'}`

if [ $PP = -r--r--r--. ]
	then
		echo " [안전] 권한   : " $PP >> $CF 2>&1
else
	if [ $PP = -rw-r--r--. ]
		then
			echo " [안전] 권한   : " $PP >> $CF 2>&1
		else
			echo " [취약] 권한   : " $PP >> $CF 2>&1
	fi
fi
if [ $PO = root ]
	then
		echo " [안전] 소유자 : " $PO >> $CF 2>&1
	else
		echo " [취약] 소유자 : " $PO >> $CF 2>&1
fi
if [ $PG = root ]
	then
		echo " [안전] 그룹   : " $PO >> $CF 2>&1
	else
		echo " [취약] 그룹   : " $PO >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo " 04-2. /etc/shadow" >> $CF 2>&1
if test `ls -l /etc/shadow | awk {'print $1'} ` = -r--------.  >> $CF 2>&1
	then
		echo " [안전] 권한   :  "`ls -l /etc/shadow | awk {'print $1'}` >> $CF 2>&1
else
	if test `ls -l /etc/shadow | awk {'print $1'} ` = ----------. >> $CF 2>&1
		then
			echo " [안전] 권한   :  "`ls -l /etc/shadow | awk {'print $1'}` >> $CF 2>&1
		else
			echo " [취약] 권한   :  "`ls -l /etc/shadow | awk {'print $1'}` >> $CF 2>&1
	fi
fi
if test `ls -l /etc/shadow | awk {'print $3'}` = root  >> $CF 2>&1
	then
		echo " [안전] 소유자 : " `ls -l /etc/shadow | awk {'print $3'}` >> $CF 2>&1
	else
		echo " [취약] 소유자 : " `ls -l /etc/shadow | awk {'print $3'}` >> $CF 2>&1
fi
if test `ls -l /etc/shadow | awk {'print $4'} ` = root  >> $CF 2>&1
	then
		echo " [안전] 그룹   :  "`ls -l /etc/shadow | awk {'print $4'}` >> $CF 2>&1
	else
		echo " [취약] 그룹   :  "`ls -l /etc/shadow | awk {'print $4'}` >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================


echo "파일 및 디렉터리 관리" 
echo "파일 및 디렉터리 관리" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "05. root홈, 패스 디렉터리 권한 및 패스 설정" >> $CF 2>&1
#목적 : 환경변수를 점검하여 비인가자가 생성한 디렉터리를 우선적으로 가리키지 않도록 설정
#위협 : 관리자 명령어를 수행했을 때 root 계정의 PATH 환경변수에 "."가 포함되면 현재 디렉터리에 명령어와 같은 이름의 악성파일이 실행될 수 있음
#echo $path했을 때 나오는 결과에 “.” 또는 “::” 포함 여부 확인

echo " root 홈 디렉터리 : " `cat /etc/passwd | grep root | sed -n '1p' | awk -F: '{print $6}'` >> $CF 2>&1

GRDP=`cat /etc/passwd | grep root | sed -n '1p' | awk -F: '{print$6}' | ls -l /../ | awk '{print $1$9}' | grep root `
a=dr-xr-x---.root


if [ $GRDP == $a ]
	then
		echo " [안전] root 홈 권한 : " $GRDP >> $CF 2>&1
	else
		echo " [취약] root 홈 권한 : " $GRDP >> $CF 2>&1
fi

echo " PATH 디렉터리 : " `env | grep PATH | awk -F= '{print $2}'` >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "06. 파일 및 디렉터리 소유자 설정" >> $CF 2>&1
#목적 : 소유자가 존재하지 않는 파일을 삭제하여 불법적 행위를 사전 방지
#위협 : 삭제된 소유자의 UID와 동일한 사용자가 해당 파일, 디렉터리에 접근 가능하여 사용자 정보 노출 가능성

if [[ -f `find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null` ]] 
	then
		echo " [안전]" >> $CF 2>&1
	else
		echo " [취약]" >> $CF 2>&1
fi

echo >> $CF 2>&1

#===============================================

echo "07. /etc/passwd 파일 소유자 및 권한 설정" >> $CF 2>&1
echo "    04-01 항목 참고" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "08. /etc/shadow 파일 소유자 및 권한 설정" >> $CF 2>&1
echo "    04-02 항목 참고" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "09. /etc/hosts 파일 소유자 및 권한 설정" >> $CF 2>&1
#목적 : 비인가자들의 임의적인 파일 변조를 방지
#위협 : hosts파일에 악의적인 시스템이 등록되어 정상적인 DNS를 우회하여 파밍사이트로 유도 가능
#/etc/hosts : IP주소와 호스트 네임을 매핑하는 파일.

HO=`ls -l /etc/hosts | awk '{print $3}'`
HP=`ls -l /etc/hosts | awk '{print $1}'`

if [ $HO = root ]
	then
		echo " [안전] hosts 파일 소유자" $HO >> $CF 2>&1
	else
		echo " [취약] hosts 파일 소유자" $HO >> $CF 2>&1
fi

if [ $HP = -rw-------. ]
	then
		echo " [안전] hosts 파일 권한" $HP >> $CF 2>&1
	else
		echo " [취약] hosts 파일 권한" $HP >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정" >> $CF 2>&1
#목적 : 비인가자들의 파일 변조를 방지
#위협 : root권한으로 불법적인 서비스를 실행할 수 있음

if test -f /etc/inetd.conf
	then
		echo " inetd.conf 파일이 존재합니다" >> $CF 2>&1
		IO=`ls -l /etc/inetd.conf | awk '{print $3}'`
		IP=`ls -l /etc/inetd.conf | awk '{print $1}'`
		if [ $IO = root ]
			then
				echo " [안전] inetd.conf 파일 소유자 : " $IO >> $CF 2>&1
			else
				echo " [취약] inetd.conf 파일 소유자 : " $IO >> $CF 2>&1
		fi
	if [ $IP = -rw-------. ]
		then
			echo " [안전] inetd.conf 파일 권한   : " $IP >> $CF 2>&1
		else
			echo " [취약] inetd.conf 파일 권한   : " $IP >> $CF 2>&1
	fi
else
	echo " inetd.conf 파일이 존재하지 않습니다" >> $CF  2>&1
fi

if test -f /etc/xinetd.conf
	then
		echo " xinetd.conf 파일이 존재합니다" >> $CF 2>&1
		XO=`ls -l /etc/xinetd.conf | awk '{print $3}'`
		XP=`ls -l /etc/xinetd.conf | awk '{print $1}'`
		if [ $XO = root ]
			then
				echo " [안전] xinetd.conf 파일 소유자 : " $XO >> $CF 2>&1
			else
				echo " [취약] xinetd.conf 파일 소유자 : " $XO >> $CF 2>&1
		fi
	if [ $XP = -rw-------. ]
		then
			echo " [안전] xinetd.conf 파일 권한   : " $XP >> $CF 2>&1
		else
			echo " [취약] xinetd.conf 파일 권한   : " $XP >> $CF 2>&1
	fi
else
	echo " xinetd.conf 파일이 존재하지 않습니다" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "11. /etc/syslog.conf 파일 소유자 및 권한 설정" >> $CF 2>&1
#목적 : syslog.conf 파일 변조를 방지
#위협 : 임의적인 파일 변조로 반드시 필요한 시스템 로그가 정상 기록되지 않을 수 있음
#참고 : centos 6버전 이상은 etc/rsyslog.conf를 사용

if test -f /etc/syslog.conf
	then
		echo " syslog.conf 파일이 존재합니다" >> $CF 2>&1
		IO=`ls -l /etc/syslog.conf | awk '{print $3}'`
		IP=`ls -l /etc/syslog.conf | awk '{print $1}'`
		if [ $IO = root ]
			then
				echo " [안전] " >> $CF 2>&1
			else
				echo " [취약] " >> $CF 2>&1
		fi
	if [ $IP = -rw-r--r--. ]
		then
			echo " [안전] " >> $CF 2>&1
		else
			echo " [취약] " >> $CF 2>&1
	fi
else
	echo " syslog.conf 파일이 존재하지 않습니다" >> $CF  2>&1
fi

if test -f /etc/rsyslog.conf
	then
		echo " rsyslog.conf 파일이 존재합니다" >> $CF 2>&1
		XO=`ls -l /etc/rsyslog.conf | awk '{print $3}'`
		XP=`ls -l /etc/rsyslog.conf | awk '{print $1}'`
		if [ $XO = root ]
			then
				echo " [안전] rsyslog.conf 파일 소유자 : " $XO >> $CF 2>&1
			else
				echo " [취약] rsyslog.conf 파일 소유자 : " $XO >> $CF 2>&1
		fi
	if [ $XP = -rw-r--r--. ]
		then
			echo " [안전] rsyslog.conf 파일 권한   : " $XP >> $CF 2>&1
		else
			echo " [취약] rsyslog.conf 파일 권한   : " $XP >> $CF 2>&1
	fi
else
	echo " rsyslog.conf 파일이 존재하지 않습니다" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "12. /etc/services 파일 소유자 및 권한 설정" >> $CF 2>&1
#목적 : 비인가자의 임의적인 파일 변조를 방지
#위협 : services파일의 접근 권한이 적절하지 않은 경우 정상적인 서비스에 장애를 일으킬 수 있음
# /etc/services : 서비스 관리에 필요한 포트들에 대해 정의 되어있음.

SO=`ls -l /etc/services | awk '{print $3}'`
SP=`ls -l /etc/services | awk '{print $1}'`

if [ $SO = root ]
	then
		echo " [안전] services 파일 소유자 : " $SO >> $CF 2>&1
	else
		echo " [취약] services 파일 소유자 : " $SO >> $CF 2>&1
fi

if [ $SP = -rw-r--r--. ]
	then
		echo " [안전] services 파일 권한   : " $SP >> $CF 2>&1
	else
		echo " [취약] services 파일 권한   : " $SP >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "13. SetUID, SetGID, Sticky Bit 설정 파일 검사" >> $CF 2>&1
#목적 : SetUID, SetGID 설정 제거로 악의적인 사용자의 권한 상승을 방지
#위협 : root권한 획득시 정상적인 서비스에 장애를 발생 가능
#SetUID(파일 소유자 권한 획득), SetGID(파일 소유 그룹 권한 획득), Sticky Bit(모든 계정이 사용하는 공용 디렉터리)

S1="13-1.SetUID.txt"
S2="13-2.SetGID.txt"
S3="13-3.Sticky_Bit.txt"
find / -user root -perm -4000 2>/dev/null > $S1 
find / -user root -perm -2000 2>/dev/null > $S2 
find / -user root -perm -1000 2>/dev/null > $S3
echo " 13-1, 13-2, 13-3.txt 파일을 참고" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" >> $CF 2>&1
#목적 : 비인가자의 환경변수 조작 방지
#위협 : 환경변수 파일이 조작되면 정상적인 서비스가 제한될 수 있음

echo " 홈 디렉터리 환경 변수 파일 수동 체크 후, 취약한지 판단" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "15. world writable 파일 점검" >> $CF 2>&1
#목적 : world writable 파일을 통해 시스템 접근 및 악의적인 코드 실행 방지
#위협 : 시스템 파일과 같은 중요 파일이 변조 될 수 있음
#world writable : 파일의 내용을 모든 사용자에게 쓰기 권한이 허용된 파일

WW="15-1.World_Writable.txt"
find / -perm -2 -ls 2>/dev/null | awk {'print $3, $11'} > $WW
echo " 15-1.txt 파일 참조" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "16. /dev에 존재하지 않는 device 파일 점검" >> $CF 2>&1
#목적 : 실제 존재하지 않는 디바이스를 제거하여 root파일 시스템 손상 및 다운의 문제를 방지
#위협 : 공격자가 악의적인 rootkit 파일을 device파일로 위장가능 

DF="16-1.Device_file.txt"
find /dev -type f -exec ls -l {} \; | awk '{print $1, $8}' > $DF
echo " 16-1.Device_file.txt 파일 참조" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "17. $HOME/.rhosts, hosts.equiv 사용 금지" >> $CF 2>&1
#목적 : 서비스 포트 차단을 통한 인증없는 원격 접속 방지
#위협 : 원격 명령어를 통해 다양한 공격이 이루어 질 수 있다. 
#/etc/hosts.equiv(서버 설정 파일), $HOME/.rhosts(개별 사용자의 설정 파일)을 사용 금지해야한다.

if [[ -f `ls -l $HOME/.rhosts 2>/dev/null` ]]
	then
		if test -f `ls -l /etc/hosts.equiv 2>/dev/null`
			then
				echo " [안전]" >> $CF 2>&1
			else
				echo " [취약]" >> $CF 2>&1
		fi
	else
		echo " [취약]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "18. 접속 IP 및 포트 제한" >> $CF 2>&1
#목적 : 허용한 호스트만 서비스를 사용하게 하여 위부자 공격 차단
#위협 : IP제한이 이루어지지 않는 경우, 다양한 네트워크 침해사고 가능성

AL="18-1.hosts.allow.txt"
AD="18-2.hosts.deny.txt"
cat /etc/hosts.allow 2>/dev/null > $AL
cat /etc/hosts.deny > $AD
echo " 생성된 18-1, 18-2.txt 참조" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "서비스 관리"
echo "서비스 관리" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "19. Finger 서비스 비활성화" >> $CF 2>&1
#목적 : Finger(사용자 정보 확인 서비스)를 통해 외부에서 사용자 정보 확인 방지
#위협 : 사용자 정보가 조회되어 권한 탈취 공격 가능성

if test -f /etc/xinetd.d/finger
	then
		if [ "`cat /etc/xinetd.d/finger  | grep disable | awk '{print $3}'`" = yes ]
			then
				echo " [안전]" >> $CF 2>&1
			else
				echo " [취약]" >> $CF 2>&1
		fi
	else
		echo " [안전]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "20. Anonymous FTP 비활성화" >> $CF 2>&1
#목적 : 익명 FTP의 접속 차단 
#위협 : 익명 로그인 후 디렉터리에 쓰기 권한이 있다면 local exploit 공격 가능성
#FTP : 원격으로 컴퓨터에 파일을 업/다운로드 하는 도구

if test -f /etc/vsftpd/vsftpd.conf
	then
		if [ "`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable | awk -F= '{print $2}'`" = NO ]
			then
				echo " [안전]" >> $CF 2>&1
			else
				echo " [취약]" >> $CF 2>&1
		fi
	else
		echo " FTP가 설치되어 있지 않습니다" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "21. r 계열 서비스 비활성화" >> $CF 2>&1
#목적 : 'r' command 사용을 통한 원격 접속을 차단
#위협 : 서비스 포트가 열린 경우, 비 인가자에 의해 중요정보 유출 및 시스템 장애 발생 가능

#'r' command : rlogin과 같이 인증 없이 관리자의 원격 접속을 가능하게 하는 명령어

if test -f /etc/xinetd.d/rlogin
	then
		if [ "`cat /etc/xinetd.d/rlogin | grep disable | awk '{print $3}'`" = yes ]
			then
				echo " [안전]" >> $CF 2>&1
			else
				echo " [취약]" >> $CF 2>&1
		fi
	else
		echo " [안전]" >> $CF 2>&1
fi

RS="21-1.r services.txt"
ls /etc/xinetd.d/r* 2>/dev/null > $RS
echo >> $CF 2>&1

#===============================================

echo "22. cron 파일 소유자 및 권한 설정" >> $CF 2>&1
#목적 : 비인가자가 allow, deny파일에 접근 방지
#위협 : 일반 사용자가 contab 명령어를 사용시 불볍 예약 파일 실행 가능성

#cron시스템 : 특정 작업을 예약하거나 반복 실행하는 기능
#allow/deny에 ID를 등록하여 화이트/블랙리스트로 해당 사용자 crontab기능 여부 결정

if test -f /etc/cron.allow
	then
		echo " cron.allow 파일이 존재합니다" >> $CF 2>&1	
		CO=`ls -l /etc/cron.allow | awk '{print $3}'`
		CP=`ls -l /etc/cron.allow | awk '{print $1}'`
		if [ $CO = root ]
			then
				echo " [안전] 파일 소유자 : " $CO >> $CF 2>&1
			else
				echo " [취약] 파일 소유자 : " $CO >> $CF 2>&1
		fi
		if [ $CP = -rw-------. ] 
			then
				echo " [안전] 파일 권한   : " $CP >> $CF 2>&1
		
			else
				if [ $CP = -rw-r--r--. ]
					then
						echo " [안전] 파일 권한   : " $CP >> $CF 2>&1
					else
						echo " [취약] 파일 권한   : " $CP >> $CF 2>&1
				fi
		fi
else
	echo " cron.allow 파일이 존재하지 않습니다" >> $CF 2>&1
	echo >> $CF 2>&1
fi

if test -f /etc/cron.deny
	then
		echo " cron.deny 파일이 존재합니다" >> $CF 2>&1	
		CO=`ls -l /etc/cron.deny | awk '{print $3}'`
		CP=`ls -l /etc/cron.deny | awk '{print $1}'`
		if [ $CO = root ]
			then
				echo " [안전] 파일 소유자 : " $CO >> $CF 2>&1
			else
				echo " [취약] 파일 소유자 : " $CO >> $CF 2>&1
		fi
		if [ $CP = -rw-------. ]
			then
				echo " [안전] 파일 권한   : " $CP >> $CF 2>&1
			else
				if [ $CP = -rw-r--r--. ]
					then
						echo " [안전] 파일 권한   : " $CP >> $CF 2>&1
					else
						echo " [취약] 파일 권한   : " $CP >> $CF 2>&1
				fi
		fi
else
	echo " cron.deny 파일이 존재하지 않습니다" >> $CF 2>&1
	echo >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "23. DoS 공격에 취약한 서비스 비활성화" >> $CF 2>&1
#목적 : 취약점이 발표된 서비스 사용금지
#위협 : 시스템 정보 유출 또는 Dos 공격의 가능성

ET=`cat /etc/services | grep echo | sed -n '1p' | awk '{print $1}'`	#클라이언트에서 보내는 메시지를 재전송
DT=`cat /etc/services | grep discard | sed -n '1p' | awk '{print $1}'`	#수신되는 임의 사용자의 데이터를 폐기
TT=`cat /etc/services | grep daytime | sed -n '1p' | awk '{print $1}'`	#클라이언트 질의에 응답하여 아스키 형태로 현재 시간과 날짜를 출력
CT=`cat /etc/services | grep chargen | sed -n '1p' | awk '{print $1}'` #임의 문자열 반환

if [ $ET = \#echo ]
	then
		echo " [안전] echo서비스가 비활성화 되어 있습니다" >> $CF 2>&1
	else
		echo " [취약] echo서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi
	
if [ $DT = \#discard ]
	then
		echo " [안전] discard 서비스가 비활성화 되어 있습니다" >> $CF 2>&1
	else
		echo " [취약] discard 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

if [ $TT = \#daytime ]
	then
		echo " [안전] daytime 서비스가 비활성화 되어 있습니다" >> $CF 2>&1
	else
		echo " [취약] daytime 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi


if [ $ET = \#chargen ]
	then
		echo " [안전] chargen 서비스가 비활성화 되어 있습니다" >> $CF 2>&1
	else
		echo " [취약] chargen 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi

echo >> $CF 2>&1

#===============================================

echo "24. NFS 서비스 비활성화" >> $CF 2>&1
#목적 : 취약한 NFS 서비스 사용으로 인한 사고 방지
#위협 : 비인가자가 시스템을 마운트하여 시스템 접근 및 파일 변조 등의 침해 가능성

#NFS란 : 원격 컴퓨터의 파일 시스템을 로컬 시스템에 마운트 하여 사용가능한 프로그램.

NC=`chkconfig --list | grep nfs`

if [ '$NC' ]
	then
		echo " [취약]" >> $CF 2>&1
	else
		echo " [안전]" >> $CF 2>&1

fi
echo >> $CF 2>&1

#===============================================

echo "25. NFS 접근통제" >> $CF 2>&1
#목적 : 접근권한이 없는 비인가자의 접근을 통제
#위협 : 접근 권한이 everyone으로 된 경우 인증절차 없이 디렉터리나 파일에 접근이 가능

echo " 해당 공유 디렉터리의 권한이 적절한지 수동으로 점검" >> $CF 2>&1
echo " showmount -e hostname명령어로 확인 후 /etc/exports 파일에 접근 가능한 호스트명 추가" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "26. automountd 제거" >> $CF 2>&1
#목적 : automountd데몬에 RPC를 보낼 수 있는 취약점 방지 
#위협 : 파일 시스템의 마운트 옵션을 변경하여 root 권한 획득 가능

#RPC란 : 다른 주고 공간에서 함수나 프로시저를 실행할 수 있는 프로세스 간 프로토콜 
#automountd란 : 클라이언트에서 자동으로 서버에 mount, unmount하는 기능

echo " 본 항목은 유닉스에만 존재" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "27. RPC 서비스 확인" >> $CF 2>&1
#목적 : 취약점이 있는 RPC 서비스를 비활성화
#위협 : 버퍼 오버플로우, Dos등의 취약점이 존재하는 RPC서비스를 통한 root 권한 획득 가능

echo " 다음과 같은 서비스 제한" >> $CF 2>&1
echo " {sadmin, rpc.*, rquotad, shell. login. exec, talk, time, discard, chargen}" >> $CF 2>&1
echo " {printer, uucp, echo, daytime, dtscpt, finger}" >> $CF 2>&1
echo >> $CF 2>&1
echo " [권장] 위의 서비스들을 중지하거나, 최신 버전의 패치 적용" >> $CF 2>&1
echo " 위의 서비스들을 중지하거나, 최신 버전의 패치를 적용했을 경우 [안전], 그렇지 않으면 [취약]" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "28. NIS, NIS+ 점검" >> $CF 2>&1
#목적 : 안전한 NIS서비스를 사용 
#위협 : 취약한 서비스인 NIS를 사용할 경우 root권한 획득 가능성이 있으나, 필요시 보안이 보완된 NIS+를 사용해야함.
#NIS란 : 패스워드나 호스트명 등 통신망의 관리나 효과적인 이용에 필요한 정보를 수록한 데이터베이스 기능

echo " 관리자의 수동 점검이 필요함" >> $CF 2>&1
echo " [권장] NIS 보다 데이터 인증이 강화된 NIS+ 사용" >> $CF 2>&1
echo " 데이터 인증이 강화된 NIS+ 사용한다면 [안전], 그렇지 않으면 [취약]" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "29. tftp, talk 서비스 비활성화" >> $CF 2>&1
#목적 : 안전하지 않거나 불필요한 서비스 제거
#위협 : 취약점이 발견된 서비스 운용시 공격 시도 가능성

TP=`cat /etc/services | grep tftp | sed -n '1p' | awk '{print $1}'`
TK=`cat /etc/services | grep talk | sed -n '1p' | awk '{print $1}'`
if [ $TP = \#tftp ]
	then
		echo " [안전] tftp 서비스가 비활성화 되어 있습니다" >> $CF 2>&1
	else
		echo " [취약] tftp 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi
	
if [ $TK = \#talk ]
	then
		echo " [안전] talk 서비스가 비활성화 되어 있습니다" >> $CF 2>&1
	else
		echo " [취약] talk 서비스가 활성화 되어 있습니다" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "30. Sendmail 버전 점검" >> $CF 2>&1
#목적 : 취약점이 없는 Sendmail 버전 사용
#위협 : 취약점이 발견된 서비스 사용시 버퍼 오버 플로우 공격 가능성

SI=`yum list installed | grep sendmail | awk '{print $1}'`
if [ '$SI' ]
	then
		SV=`echo \$Z | /usr/lib/sendmail -bt -d0 | sed -n '1p' | awk '{print $2}'`
		echo " sendmail 버전 : $SV" >> $CF 2>&1
		echo " 최신 버전으로 적용되어 있다면 [안전], 그렇지 않으면 [취약]" >> $CF 2>&1
	else
		echo " sendmail이 설치되어 있지 않습니다 " >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "31. 스팸 메일 릴레이 제한" >> $CF 2>&1
#목적 : 스팸 메일과 서버 과부하 방지
#위협 : 악의적인 목적으로 스팸 메일 서버로 사용하거나 Dos공격의 대상이 될수 있으므로 /etc/mail/access 파일에 스팸관련 설정이 있어야함.

if [ '$SI' ]
	then
		SP=`ls -l /etc/mail/access 2>/dev/null | awk '{print $1}'`  >> $CF 2>&1
		if [ $SP ]
			then
				SP=`ls -l /etc/mail/access 2>/dev/null | awk '{print $1}'`  >> $CF 2>&1
				echo " [안전] 스팸 메일 관련 설정 사항이 저장된 파일이 존재합니다" >> $CF 2>&1
			else
				echo " [취약] 스팸 메일 관련 설정 파일이 존재하지 않습니다" >> $CF 2>&1
		fi
	else
		echo " sendmail이 설치되어 있지 않습니다" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "32. 일반사용자의 Sendmail 실행 방지" >> $CF 2>&1
#목적 : 일반 사용자의 q옵션을 제한하여 sendmail 설정 및 메일 큐를 강제적으로 drop 할 수 없게 제한하여 SMTP(메일 전송시 사용되는 프로토콜) 서비스 오류 방지
#위협 : 일반 사용자가 q옵션을 이용해서 메일 큐, sendmail 설정을 보거나 메일 큐를 drop할 수 있어 악의적으로 오류 발생가능

#/etc/mail/sendmail.cf 파일 내의 PrivacyOptions 옵션에 uthwarnings,novrfy,noexpn,restrictqrun이 있어야함.
 
if [ '$SI' ]
	then
		SV=`cat /etc/mail/sendmail.cf | grep PrivacyOptions | awk -F= '{print $2}'`
		
		if [ '$SV' = authwarnings,novrfy,noexpn,restrictqrun ]
			then 
				echo " [안전]" >> $CF 2>&1
			else
				echo " [취약]" >> $CF 2>&1
		fi
	else
		echo " [취약]" >> $CF 2>&1
fi
echo >> $CF 2>&1
	
#===============================================	

echo "33. DNS 보안 버전 패치" >> $CF 2>&1
#목적 : 취약점이 발견되지 않은 BIND 버전의 사용
#위협 : 취약할 버전일 경우 서비스 거부 공격, DNS 서버 원격 침입등의 취약성이 존재

#BIND : BSD(유닉스 운영체제의 종류)기반의 시스템을 위한 DNS
#최신버전 다운로드 사이트 : http://www.isc/org.downloads/

DS=`named -v`
echo " DNS버전 : $DS " >> $CF 2>&1
echo " DNS 보안 패치가 최신일경우 [안전], 그렇지 않으면 [취약]" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "34. DNS Zone Transfer 설정" >> $CF 2>&1
#목적 : 허가되지 않은 사용자에게 DNS Zone Transfer를 제한함으로 호스트,시스템 등의 정보 유출을 방지
#위협 : DNS Zone Transfer가 제한되지 않으면 호스트,시스템 등의 정보 유출 가능성. 따라서 Primary Name Server에는 Zone Transfer를 허용하는 서버를 지정하고, Secondary Server에는 Zone Transfer를 거부해야함.

#Primary (주 영역) : Read / Write, Secondary (보조 영역) : Read Only
#DNS Zone Transfer : Primary와 Secondary간의 Zone 정보를 일관성있게 유지하는 기능
#Zone파일 : 도메인 네임 서버를 통해 연결되도록 개별 호스트간의 정보를 가짐

#DNS사용시 etc/named.conf파일의 allow-transfer와 xfrnets 값에 각각 Zone파일 전송허용 ip를 적어주어야함.
#DNS를 사용하지 않는 경우 DNS 서비스 데몬 중지.

echo " [권장] DNS Zone Transfer를 허가된 사용자에게만 허용해야 함" >> $CF 2>&1
echo " DNS Zone Transfer를 모든 사용자에게 허용했을 경우 [취약]" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "35. Apache 디렉터리 리스팅 제거" >> $CF 2>&1
#목적 : 외부에서 디렉터리 내의 파일 리스트 접근 거부
#위협 : 소스파일이나 중요 파일이 노출될 수 있음. 따라서 설정파일 내의 Indexes 키워드를 제거.

GV=`cat /etc/httpd/conf/httpd.conf | grep Options | sed -n '1p'`
if [[ $GV == *Indexes* ]]
	then
		echo " [취약]" >> $CF 2>&1
	else
		echo " [안전]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "36. Apache 웹 프로세스 권한 제한" >> $CF 2>&1
#목적 : Apache 데몬에서 root권한을 하용함으로, 피해확산 방지
#위협 : Apache 권한이 탈취당할 경우 권한이 root하면 시스템 전체의 제어권을 탈취 당하게 됨. 따라서 권한을 다르게 지정해주어야함.

UP=`cat /etc/httpd/conf/httpd.conf | grep User | sed -n '3p' | awk '{print $2}'`
GP=`cat /etc/httpd/conf/httpd.conf | grep Group | sed -n '6p' | awk '{print $2}'`

if [ "$UP" != root ]
	then
		echo " [안전] 현재 설정된 웹 프로세스 User 권한  :" $UP >> $CF 2>&1
	else
		echo " [취약] 현재 설정된 웹 프로세스 User 권한  :" $UP >> $CF 2>&1
fi

if [ "$GP" != root ]
	then
		echo " [안전] 현재 설정된 웹 프로세스 Group 권한 :" $GP >> $CF 2>&1
	else
		echo " [취약] 현재 설정된 웹 프로세스 Group 권한 :" $GP >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "37. Apache 상위 디렉터리 접근 금지" >> $CF 2>&1
#목적 : 상위 경로 이동으로 시스템 구조 및 중요파일 위치 보호
#위협 : 권한이 없는 자가 상위경로 이동이 가능하면 중요파일이 노출 될 수 있다. 따라서 AllowOverride옵션이 AuthConfig 또는 All 이어야함.

GC=`cat /etc/httpd/conf/httpd.conf  | grep AllowOverride | sed -n '1p' | awk '{print $2}'`

if [ $GC = None ]
	then
		echo " [취약]" >> $CF 2>&1
	else
		echo " [안전]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "38. Apache 불필요한 파일 제거" >> $CF 2>&1
#목적 : 서버 설치시 기본으로 설치되는 불필요한 파일을 제거
#위협 : htdocs 디렉터리 내 메뉴얼 파일은 시스템 관련 정보를 노출 할 수 있음
 
echo " [권장] 웹 서버를 정기적으로 검사하여 불필요한 파일을 제거" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "39. Apache 링크 사용 금지" >> $CF 2>&1
#심볼릭 링크란? window바로가기와 같은 링크 개념
#aliases란? PreparedStatement와 같이 명령어를 쉽게 불러오기 위한 개념
#목적 : 무분별한 심볼릭 링크, aliases 사용제한으로 시스템 구조와 권한 보호
#위협 : 시스템 root디렉터리에 링크를 걸게 되면 일반 웹 사용자 권한으로 모든 파일에 접근할 수 있게 됨. 따라서 FollowSymLinks 키워드가 존재하지 않아야함.

if [[ $GV == *FollowSymLinks* ]]
	then
		echo " [취약]" >> $CF 2>&1
	else
		echo " [안전]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "40. Apache 파일 업로드 및 다운로드 제한" >> $CF 2>&1
#목적 : 업로드, 다운로드 기능 사용시 서버 과부하 방지 및 효율적 자원 분배
#위협 : 대용량 파일의 반복 업로드로 서버자원을 고갈시킬 위험이 있음. 따라서 저장되는 파일 크기와 post로 전달되는 파일크기의 제한이 필요함

US=`cat /etc/php.ini 2>/dev/null |  grep post_max_size | awk '{print $3}'`
DS=`cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep LimitRequestBody`

if [ $US ]
	then
		echo " [안전] 업로드 가능한 파일의 최대 용량   : "$US >> $CF 2>&1
	else
		echo " [취약] 업로드 가능한 파일의 최대 용량   : 제한없음" >> $CF 2>&1
fi

if [ $DS ]
	then
		echo " [안전] 다운로드 가능한 파일의 최대 용량 : "$DS >> $CF 2>&1
	else
		echo " [취약] 다운로드 가능한 파일의 최대 용량 : 제한없음" >> $CF 2>&1
fi

echo >> $CF 2>&1

#===============================================

echo "41. Apache 웹 서비스 영역 분리" >> $CF 2>&1
#목적 : 웹 서비스 영역와 시스템 영역을 분리하여 웹 서비스 침투 사고가 시스템 사고로 확장됨을 방지
#위협 : 웹 서버의 루트 디렉터리와 os의 루트 디렉터리를 다르게 지정해야함

DR=`cat /etc/httpd/conf/httpd.conf | grep DocumentRoot | sed -n '2p' | awk '{print $2}'`
DD="/var/www/html"
if [ $DR=$DD ]
	then
		echo " [취약]" >> $CF 2>&1
	else
		echo " [안전]" >> $CF 2>&1
fi
echo >> $CF 2>&1

#===============================================

echo "패치 관리"
echo "패치 관리" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "42. 최신 보안패치 및 벤더 권고사항 적용" >> $CF 2>&1
#목적 : 주기적인 패치 적용으로 보안성, 안정성 확보
#위협 : 최신 보안 패치가 이루어지지 않으면, 이미 알려진 취약점을 통해 침해사고 가능성

echo " [권장] 'yum update (-y)' 명령어를 사용하여 설치된 패키지의 최신 패치를 설치" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "로그 관리"
echo "로그 관리" >> $CF 2>&1
echo >> $CF 2>&1

#===============================================

echo "43. 로그의 정기적 검토 및 보고" >> $CF 2>&1
#목적 : 정기적인 로그 검토를 통해 외부 침투 여부를 파악하기 위함
#위협 : 로그 검토 및 보고 절차가 없는 경우 외부 침입 시도의 식별이 어려움

echo " [권장] 로그 기록에 대해 정기적 검토, 분석, 이에 대한 리포트 작성 및 보고" >> $CF 2>&1
echo >> $CF 2>&1

