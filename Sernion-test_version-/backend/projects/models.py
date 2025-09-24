"""
Models for projects app.
"""
from django.db import models
from django.conf import settings
from django.utils import timezone


class Project(models.Model):
    """
    Model for annotation projects.
    """
    PROJECT_TYPES = [
        ('audio', 'Audio Annotation'),
        ('video', 'Video Annotation'),
        ('image', 'Image Annotation'),
        ('text', 'Text Annotation'),
    ]
    
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('completed', 'Completed'),
        ('archived', 'Archived'),
    ]
    
    # Basic information
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    project_type = models.CharField(max_length=20, choices=PROJECT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    # Ownership and collaboration
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='owned_projects')
    collaborators = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='collaborated_projects', blank=True)
    
    # Settings
    is_public = models.BooleanField(default=False)
    allow_anonymous_annotations = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'projects'
        ordering = ['-updated_at']
    
    def __str__(self):
        return self.name
    
    @property
    def total_datasets(self):
        """Get total number of datasets in this project."""
        return self.datasets.count()
    
    @property
    def total_annotations(self):
        """Get total number of annotations in this project."""
        return sum(dataset.total_annotations for dataset in self.datasets.all())


class Dataset(models.Model):
    """
    Model for datasets within projects.
    """
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='datasets')
    
    # File information
    file_path = models.CharField(max_length=500)  # Path to the dataset file
    file_size = models.BigIntegerField(default=0)  # Size in bytes
    file_type = models.CharField(max_length=50)  # Type of file (mp3, mp4, jpg, etc.)
    
    # Metadata
    metadata = models.JSONField(default=dict, blank=True)  # Additional metadata
    
    # Status
    is_processed = models.BooleanField(default=False)
    processing_status = models.CharField(max_length=50, default='pending')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'datasets'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.project.name}"
    
    @property
    def total_annotations(self):
        """Get total number of annotations for this dataset."""
        return self.annotations.count()


class Annotation(models.Model):
    """
    Model for annotations.
    """
    ANNOTATION_TYPES = [
        ('classification', 'Classification'),
        ('segmentation', 'Segmentation'),
        ('bounding_box', 'Bounding Box'),
        ('keypoint', 'Keypoint'),
        ('transcription', 'Transcription'),
        ('translation', 'Translation'),
    ]
    
    # Basic information
    dataset = models.ForeignKey(Dataset, on_delete=models.CASCADE, related_name='annotations')
    annotator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='annotations')
    annotation_type = models.CharField(max_length=20, choices=ANNOTATION_TYPES)
    
    # Content
    content = models.JSONField()  # Flexible content storage
    confidence_score = models.FloatField(default=1.0)  # Confidence in the annotation
    
    # Status
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='verified_annotations'
    )
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'annotations'
        ordering = ['-created_at']
        unique_together = ['dataset', 'annotator', 'annotation_type']
    
    def __str__(self):
        return f"{self.annotation_type} by {self.annotator.username} on {self.dataset.name}"
    
    def verify(self, verified_by_user):
        """Mark annotation as verified."""
        self.is_verified = True
        self.verified_by = verified_by_user
        self.verified_at = timezone.now()
        self.save()


class AnnotationTemplate(models.Model):
    """
    Model for annotation templates/schemas.
    """
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='annotation_templates')
    
    # Schema definition
    schema = models.JSONField()  # JSON schema for the annotation structure
    
    # Settings
    is_default = models.BooleanField(default=False)
    is_required = models.BooleanField(default=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'annotation_templates'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} - {self.project.name}"


class ProjectInvitation(models.Model):
    """
    Model for project invitations.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('declined', 'Declined'),
        ('expired', 'Expired'),
    ]
    
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='invitations')
    inviter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_invitations')
    invitee_email = models.EmailField()
    invitee = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True, 
        related_name='received_invitations'
    )
    
    # Invitation details
    role = models.CharField(max_length=50, default='annotator')  # annotator, reviewer, admin
    message = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Token for invitation link
    token = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'project_invitations'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Invitation to {self.invitee_email} for {self.project.name}"
    
    @property
    def is_expired(self):
        """Check if invitation has expired."""
        return timezone.now() > self.expires_at
