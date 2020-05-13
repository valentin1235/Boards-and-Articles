# How to run
1. 프로젝트를 클론합니다
2. 가상환경을 만듭니다(작성자는 pycharm venv 사용)
3. 가상환경 안에서 pip install -r requirements.txt 명령어를 통해서 필요 라이브러리를 다운받습니다.
4. config.py 파일을 connection.py 파일과 같은 디렉토리에 생성해주고 아래와같은 config 내용을 넣습니다(이프로젝트는 postgresql를 데이터베이스로 사용하고 redis를 세션 저장공간으로 사용합니다)

         DATABASES = {
             'user': 'database_user_name',
             'password': 'database_password',
             'host': 'host',
             'port': 3306,
             'database': 'database_name',
         }

         REDIS = {
             'host': 'host',
             'port': 6379
         }

         SECRET = {
             'secret_key':'secret_key',
             'algorithm': 'HS256'
         }
5. alembic upgrade head 명령어를 실행해서 데이터베이스에 테이블을 생성합니다.
6. [API document](https://documenter.getpostman.com/view/10893095/SzmYA237?version=latest)를 참조해서 sign-up 부터 차례로 api를 호출할 수 있습니다.

# Project Introduction
##### [프로젝트 후기](https://velog.io/@valentin123/Project4-about-boards-articles-project)


Simple board and article create, read, update and delete project. 

+ Project Period  : 2020.04.27 - 2020.05.01

+ Member         : (backend) Heechul Yoon
         

# API Description
[로그인 데코레이터]
+ request로 들어온 토큰을 decode해서 토큰 유효성 검사
+ 토큰 확인 후 성공 시 유저정보를 flask g 객체에 저장

[회원가입]
+ flask_request_validator를 통한 request body 유효성 검사(이메일 중복체크, 이메일 형식체크, 권한타입체크 등)
+ bcrypt 비밀번호 암호화 
+ 회원가입 성공 시 jwt 토큰(유효기간 6일)을 redis에 uuid를 키(key)로 하여 저장

         "8b3b9a0b-5fbc-47d6-a113-5479d33aec7f":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6OCwiZXhwIjoxNTg4NzY0MTU3fQ.W_gWd9sXPpLaY6teppDYgCKRW8rFz8O5-_vMcfzS6jM"
+ redis에 저장된 uuid 키(key)를 데이터베이스에 random_key테이블에 저장 

[로그인]
+ flask_request_validator를 통한 이메일, 패스워드 유효성검사
+ bcrypt checkpw를 통해서 해쉬된 패스워드 비교
+ 로그인 성공 시 jwt 토큰(유효기간 6일)을 redis에 uuid를 키(key)로 하여 저장

         "8b3b9a0b-5fbc-47d6-a113-5479d33aec7f":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6OCwiZXhwIjoxNTg4NzY0MTU3fQ.W_gWd9sXPpLaY6teppDYgCKRW8rFz8O5-_vMcfzS6jM"
+ redis에 저장된 uuid 키(key)를 데이터베이스에 random_key테이블에 저장 

[로그아웃]
+ 로그인 할 때 리턴 한 redis 리소스 접근 key를 request body로 받음
+ 토큰 접근 key를 redis에서 삭제해서 다음 api 요청 시 토큰을 찾을 수 없도록 함 

[게시판 생성]
+ 유효성검사 : 마스터권한이 아닐 시 400 리턴
+ 유효성검사 : 생성하려는 게시판 이름이 중복된 이름이면 400리턴

[게시판 리스트 표출]
+ 삭제되지 않은 게시판의 리스트를 표출함
+ 검색 기능 : 게시판 이름을 통한 검색. like를 통해서 해당 글자가 포함되면 검색하는 기능
+ pagination : offset과 limit을 쿼리 파라미터로 받아서 페이지네이션 구현

[게시판 이름 수정]
+ 유효성검사 : 마스터권한이 아닐시 400리턴
+ path parameter로 수정 대상 게시판 아이디를 받음
+ 게시판 테이블에 수정자 컬럼 업데이트

[게시판 삭제]
+ 유효성검사 : 마스터권한이 아닐시 400리턴
+ path parameter로 게시판 아이디를 받고 body로 게시판 삭제 True를 받음, 삭제 api이기 때문에 True이외의 액션은 400애러 처리
+ boards 테이블의 is_deleted 컬럼의 값을 False에서 True로 바꿔주는 soft delete
+ 삭제하고자 하는 게시판이 이미 삭제되어있으면 400 리턴
+ 게시판 테이블에 수정자 컬럼 업데이트
+ 게시판을 삭제하고 해당 게시판에 작성된 모든 게시물도 삭제함

[게시물 생성]
+ path 파라미터로 게시판 아이디를 받고 해당 게시판에 게시물 생성
+ flask validator를 통해서 게시물 제목, 게시물 내용 유효성 검사
+ 이미 삭제된 게시판에 게시물을 생성하려는 경우 404 애러 리턴

[게시물 리스트 표출]
+ path 파라미터로 게시판 아이디를 받고 해당 게시판의 게시물 리스트 표출
+ 이미 삭제된 게시판의 게시물 리스트를 가져오려는 경우 404리턴
+ 삭제되지 않은(is_deleted==false) 게시물을 리스트 형식으로 최근 생성된 순으로 정렬해서 가져옴
+ 검색기능 : 게시물 제목과 작성자를 통한 검색. like를 통해서 해당 글자가 포함되면 검색하는 기능
+ pagination : offset과 limit을 쿼리 파라미터로 받아서 페이지네이션 구현

[게시물 상세 정보 표출]
+ path파라미터로 게시판아이디와 게시물 아이디를 같이 받아서 게시물 상세정보 표출
+ 이미 삭제된 게시판 또는 게시물의 정보를 가져오려는 경우 404 리턴

[게시물 수정]
+ path 파라미터로 게시판 아이디와 게시물 아이디를 받아서 해당 게시물의 내용을 수정
+ flask validator를 통해서 게시물 제목과 게시물 내용의 유효성검사
+ 게시물의 생성자가 게시물의 수정하려는 경우가 아닌 경우 403리턴
+ 이미 삭제된 게시판 또는 게시물을 수정하려는 경우 404 리턴
+ 게시물 제목 또는 게시물 내용을 업데이트 하고, 게시물 수정자를 업데이트함.

[게시물 삭제]
+ path 파라미터로 게시판 아이디와 게시물 아이디를 받고, body로 삭제여부 True를 받아서 해당 게시물의 내용을 삭제
+ 섹제 api이기 때문에 True이외의 액션은 400리턴
+ 게시물의 생성자가 아닌데 게시물을 삭제하려는 경우 403리턴
+ 이미 삭제된 게시판 또는 게시물을 삭제하려는 경우 404 리턴
+ is_deleted를 True로 바꿔주고 수정자 업데이트

[대시보드 표출]
+ 게시판 리스트 표출 함수, 게시물 리스트 표출 함수 재활용
+ 존재하는 게시판에 가장 최근의 게시물리스트 N개를 가져온다.
+ 게시판 리스트표출 함수를 호출해서 게시판 리스트를 가져옴.
+ 게시물 리스트표출 함수를 호출해서 게시판 게시판 id를 parameter로 넣어서 해당 게시판의 게시물 리스트를 가져옴.

# Features
+ [POST] Sign-in and Sign-up features.
+ [POST] Log out feature.
+ [POST] Create board under the master authorization.
+ [GET] Display all board list.
+ [PUT] Edit board name under the master authorization.
+ [DELETE] Delete board under the master authorization.
+ [POST] Create an article in a board.
+ [GET] Display all articles in a board.
+ [PUT] Edit article title or contents belong to a user. 
+ [DELETE] Delete article belong to a user.
+ [GET] Display recent articles belong to boards.

# Technologies(Backend)
+ Python 3.8.0 : language
+ Pycharm venv : virtual environment
+ Flask 1.1.2  : web framework
+ Git          : cooperation and version management tool
+ Redis        : Caching database
+ PostgreSQL   : Database
+ Alembic      : migration tool
+ SQLalchemy   : ORM(Object Relational Mapping)
+ Bcrypt       : password hashing
+ JWT          : token generating

# API Documentation
+ [Boards & Articles](https://documenter.getpostman.com/view/10893095/SzmYA237?version=latest)

# Database Modeling
![ERD](https://brandi-intern.s3.ap-northeast-2.amazonaws.com/Board_and_Article.png)
