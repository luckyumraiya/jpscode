from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

#  Custom User Manager


class UserManager(BaseUserManager):
    def create_user(self, email, username, name, tc, comp, usr,password=None, password2=None):
        """
        Creates and saves a User with the given email, name, tc and password.
        """
        if not username:
            raise ValueError('User must have an Username')

        user = self.model(
            username=self.normalize_email(username),
            name=name,
            tc=tc,
            email=email,
            comp=comp,
            usr=usr,
          
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, name, tc, usr, password=None):
        """
        Creates and saves a superuser with the given email, name, tc and password.
        """
        user = self.create_user(
            email=email,
            password=password,
            name=name,
            tc=tc,
            username=username,
            usr=usr,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

#  Custom User Model


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='Email',
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    comp = models.CharField(max_length=100, default=True)
    usr = models.CharField(max_length=100, default=True)
    username = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=100)
    tc = models.BooleanField()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['name', 'tc', 'email', 'comp', 'usr']

    def __str__(self):
        # return self.get_username
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


class MenuGroup(models.Model):
    grpname = models.CharField(max_length=20)
    sequence = models.CharField(max_length=1)
    inactive = models.BooleanField()
    note = models.CharField(max_length=50)
    
    def __str__(self):
        return self.grpname

class MenuMaster(models.Model):
    groupname = models.ForeignKey(MenuGroup, on_delete=models.CASCADE)
    menuname = models.CharField(max_length=20)
    taskname = models.CharField(max_length=20)

    def __str__(self):
        return self.groupname

class TaskMaster(models.Model):
    task = models.ForeignKey(MenuMaster, on_delete=models.CASCADE)
    description = models.CharField(max_length=100)
    pyname = models.CharField(max_length=30)
    inactivetask = models.BooleanField()
    notetask = models.CharField(max_length=50)
    lastupdateuser = models.ForeignKey(User, on_delete=models.CASCADE)
    lastupdatedate = models.DateField(auto_now=True)
    lastupdatetime = models.TimeField(auto_now=True)
    lastupdatetask = models.CharField(max_length=50)
    lastupdateip = models.CharField(max_length=20)

    def __str__(self):
        return self.task

    # @property
    # def ipadd(self):
    #     lastip=socket.gethostbyname(socket.gethostname())
    #     self.lastupdateip=lastip
    #     return lastip

# class UserTaskAccess(models.Model):
#     usercompany=models.ForeignKey(User,on_delete=models.CASCADE)
#     useracc=models.ForeignKey(User,on_delete=models.CASCADE)
#     taskacc=models.ForeignKey(MenuMaster,on_delete=models.CASCADE)
#     inactivetaskacc=models.BooleanField()
#     notetaskacc=models.CharField(max_length=50)
#     viewaccess=models.BooleanField()
#     addaccess=models.BooleanField()
#     editaccess=models.BooleanField()
#     deleteaccess=models.BooleanField()
#     inactiveaccess=models.BooleanField()
#     lastupdateuseracc=models.CharField(max_length=50)
#     lastupdatedateacc=models.DateField(auto_now=True)
#     lastupdatetimeacc=models.TimeField(auto_now=True)
#     lastupdatetaskacc=models.CharField(max_length=50)
#     lastupdateipacc=models.CharField(max_length=20)


class UserTaskAccess(models.Model):
    useracc = models.ForeignKey(User, on_delete=models.CASCADE)
    taskacc = models.ForeignKey(MenuMaster, on_delete=models.CASCADE)
    inactivetaskacc = models.BooleanField()
    notetaskacc = models.CharField(max_length=50)
    viewaccess = models.BooleanField()
    addaccess = models.BooleanField()
    editaccess = models.BooleanField()
    deleteaccess = models.BooleanField()
    inactiveaccess = models.BooleanField()
    lastupdateuseracc = models.CharField(max_length=50)
    lastupdatedateacc = models.DateField(auto_now=True)
    lastupdatetimeacc = models.TimeField(auto_now=True)
    lastupdatetaskacc = models.CharField(max_length=50)
    lastupdateipacc = models.CharField(max_length=20)
    
    def __str__(self):
       return self.useracc


class FieldMaster(models.Model):
    fieldmas = models.CharField(max_length=50)
    placeholdermsg = models.CharField(max_length=100)
    errormsg = models.CharField(max_length=100)
    inactivefield = models.BooleanField()
    notefield = models.CharField(max_length=50)
    lastupdateuserfield = models.CharField(max_length=50)
    lastupdatedatefield = models.DateField(auto_now=True)
    lastupdatetimefield = models.TimeField(auto_now=True)
    lastupdatetaskfield = models.CharField(max_length=50)
    lastupdateipfield = models.CharField(max_length=20)
    
    def __str__(self):
        return self.fieldmas

# class TaskFieldMaster(models.Model):
#     companytaskfield=models.ForeignKey(User,on_delete=models.CASCADE)
#     usertaskfield=models.ForeignKey(User,on_delete=models.CASCADE)
#     tasktaskfield=models.ForeignKey(MenuMaster,on_delete=models.CASCADE)
#     fieldtaskfield=models.ForeignKey(FieldMaster,on_delete=models.CASCADE)
#     restricted=models.BooleanField()
#     inactivetaskfield=models.BooleanField()
#     notetaskfield=models.CharField(max_length=50)
#     lastupdateuseracc=models.CharField(max_length=50)
#     lastupdatedateacc=models.DateField(auto_now=True)
#     lastupdatetimeacc=models.TimeField(auto_now=True)
#     lastupdatetaskacc=models.CharField(max_length=50)
#     lastupdateipacc=models.CharField(max_length=20)

class TaskFieldMaster(models.Model):
    usertaskfield = models.ForeignKey(User, on_delete=models.CASCADE)
    tasktaskfield = models.ForeignKey(MenuMaster, on_delete=models.CASCADE)
    fieldtaskfield = models.ForeignKey(FieldMaster, on_delete=models.CASCADE)
    restricted = models.BooleanField()
    inactivetaskfield = models.BooleanField()
    notetaskfield = models.CharField(max_length=50)
    lastupdateusertaskfield = models.CharField(max_length=50)
    lastupdatedatetaskfield = models.DateField(auto_now=True)
    lastupdatetimetaskfield = models.TimeField(auto_now=True)
    lastupdatetasktaskfield = models.CharField(max_length=50)
    lastupdateiptaskfield = models.CharField(max_length=20)

    def __str__(self):
        return self.usertaskfield
