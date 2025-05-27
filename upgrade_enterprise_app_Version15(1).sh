echo "==> MASTER UPGRADE: Upgrading both backend and frontend to latest enterprise features..."

# ===== BACKEND UPGRADE =====
echo "==> Backend: Installing/upgrading dependencies and API for enterprise forms..."

cd backend

echo "==> Ensuring Django REST Framework and PostgreSQL driver in requirements.txt..."
grep -qxF "djangorestframework==3.14.0" requirements.txt || echo "djangorestframework==3.14.0" >> requirements.txt
grep -qxF "django-cors-headers==4.3.1" requirements.txt || echo "django-cors-headers==4.3.1" >> requirements.txt
grep -qxF "psycopg2-binary==2.9.7" requirements.txt || echo "psycopg2-binary==2.9.7" >> requirements.txt
pip install -r requirements.txt

# --- 1. Models: forms, submissions, style template, users assigned ---
mkdir -p forms
cat > forms/models.py <<'EOF'
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class StyleTemplate(models.Model):
    name = models.CharField(max_length=100)
    css = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class FormDefinition(models.Model):
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    structure = models.JSONField(help_text="Form schema as JSON")
    steps = models.JSONField(null=True, blank=True, help_text="List of steps for multi-step forms")
    style_template = models.ForeignKey(StyleTemplate, null=True, blank=True, on_delete=models.SET_NULL)
    assigned_users = models.ManyToManyField(User, blank=True, related_name="assigned_forms")
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_forms")
    created_at = models.DateTimeField(auto_now_add=True)

class FormSubmission(models.Model):
    form = models.ForeignKey(FormDefinition, on_delete=models.CASCADE, related_name="submissions")
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    data = models.JSONField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=32, default="Submitted")
EOF

# --- 2. Serializers ---
cat > forms/serializers.py <<'EOF'
from rest_framework import serializers
from .models import FormDefinition, FormSubmission, StyleTemplate

class StyleTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = StyleTemplate
        fields = ["id", "name", "css", "created_at"]

class FormDefinitionSerializer(serializers.ModelSerializer):
    style_template = StyleTemplateSerializer(read_only=True)
    class Meta:
        model = FormDefinition
        fields = ["id", "name", "description", "structure", "steps", "style_template"]

class FormSubmissionSerializer(serializers.ModelSerializer):
    form_name = serializers.CharField(source="form.name", read_only=True)
    class Meta:
        model = FormSubmission
        fields = ["id", "form", "form_name", "user", "data", "submitted_at", "status"]
        read_only_fields = ["submitted_at", "status", "form_name"]
EOF

# --- 3. Views: API Endpoints ---
cat > forms/views.py <<'EOF'
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from .models import FormDefinition, FormSubmission
from .serializers import FormDefinitionSerializer, FormSubmissionSerializer

class UserFormsListView(generics.ListAPIView):
    serializer_class = FormDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        return FormDefinition.objects.filter(assigned_users=self.request.user).order_by("name")

class FormDetailView(generics.RetrieveAPIView):
    serializer_class = FormDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = FormDefinition.objects.all()

class UserSubmissionsListView(generics.ListAPIView):
    serializer_class = FormSubmissionSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        return FormSubmission.objects.filter(user=self.request.user).order_by("-submitted_at")

class FormSubmissionSyncView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        data = request.data
        if isinstance(data, list):
            results = []
            for item in data:
                res = self._save_submission(item, request.user)
                results.append(res)
            return Response(results, status=status.HTTP_201_CREATED)
        else:
            res = self._save_submission(data, request.user)
            return Response(res, status=status.HTTP_201_CREATED)
    def _save_submission(self, data, user):
        form_id = data.get("form") or data.get("form_id")
        form = get_object_or_404(FormDefinition, id=form_id)
        submission, created = FormSubmission.objects.update_or_create(
            user=user, form=form,
            defaults={"data": data.get("data", {}), "status": "Submitted"}
        )
        return FormSubmissionSerializer(submission).data
EOF

# --- 4. URLs ---
cat > forms/urls.py <<'EOF'
from django.urls import path
from .views import (
    UserFormsListView, FormDetailView, UserSubmissionsListView, FormSubmissionSyncView
)

urlpatterns = [
    path("forms/", UserFormsListView.as_view(), name="user_forms"),
    path("forms/<int:pk>/", FormDetailView.as_view(), name="form_detail"),
    path("forms/submissions/", UserSubmissionsListView.as_view(), name="user_submissions"),
    path("forms/submit/", FormSubmissionSyncView.as_view(), name="form_submit"),
]
EOF

# --- 5. Patch project urls.py if needed ---
cd config
if ! grep -q "include('forms.urls')" urls.py; then
    sed -i "/from django.urls import path/a\\
from django.urls import include
" urls.py
    sed -i "/urlpatterns = \[/a\\
    path('api/', include('forms.urls')),
" urls.py
fi
cd ..

# --- 6. Run migrations ---
python manage.py makemigrations forms
python manage.py migrate

cd ..

# ===== FRONTEND UPGRADE =====
echo "==> Frontend: Installing user PWA features (dynamic forms, offline cache/sync)..."
cd frontend

# 1. Only required dependencies for User PWA
npm install idb react-router-dom

# 2. IndexedDB helper for offline cache
mkdir -p src/pwa
cat > src/pwa/formCache.js <<'EOF'
import { openDB } from "idb";

const DB_NAME = "UserPWAFormCache";
const SUBMISSION_STORE = "submissions";
const FORM_STORE = "forms";

export async function getDB() {
  return openDB(DB_NAME, 1, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(SUBMISSION_STORE))
        db.createObjectStore(SUBMISSION_STORE, { autoIncrement: true });
      if (!db.objectStoreNames.contains(FORM_STORE))
        db.createObjectStore(FORM_STORE, { keyPath: "id" });
    }
  });
}

// Submission cache
export async function addSubmission(sub) {
  const db = await getDB();
  await db.add(SUBMISSION_STORE, sub);
}
export async function getAllSubmissions() {
  const db = await getDB();
  return db.getAll(SUBMISSION_STORE);
}
export async function clearSubmissions() {
  const db = await getDB();
  await db.clear(SUBMISSION_STORE);
}

// Cached forms for offline viewing/filling
export async function cacheForm(form) {
  const db = await getDB();
  await db.put(FORM_STORE, form);
}
export async function getCachedForm(id) {
  const db = await getDB();
  return db.get(FORM_STORE, id);
}
EOF

# 3. Multi-step dynamic form component (with review and offline cache/sync)
cat > src/pwa/MultiStepDynamicForm.js <<'EOF'
import React, { useState } from "react";
import { addSubmission } from "./formCache";

export default function MultiStepDynamicForm({ form, onComplete, offline }) {
  const steps = form.steps || [{ fields: form.structure }];
  const [stepIdx, setStepIdx] = useState(0);
  const [values, setValues] = useState({});
  const [review, setReview] = useState(false);

  const handleChange = (e) => {
    setValues((v) => ({ ...v, [e.target.name]: e.target.value }));
  };

  const next = () => setStepIdx((i) => Math.min(i + 1, steps.length - 1));
  const prev = () => setStepIdx((i) => Math.max(i - 1, 0));

  const gotoReview = (e) => { e.preventDefault(); setReview(true); };
  const edit = () => setReview(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const payload = {
      form_id: form.id,
      data: values,
      timestamp: new Date().toISOString()
    };
    if (navigator.onLine) {
      try {
        await fetch("/api/forms/submit/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        onComplete("Submitted online!");
      } catch {
        await addSubmission(payload);
        onComplete("Saved offline, will sync!");
      }
    } else {
      await addSubmission(payload);
      onComplete("Saved offline, will sync!");
    }
  };

  if (review) {
    return (
      <form onSubmit={handleSubmit}>
        <h3>Review Your Answers</h3>
        {steps.flatMap((step) => step.fields).map((field) => (
          <div key={field.name}>
            <b>{field.label || field.name}:</b> {values[field.name] || ""}
          </div>
        ))}
        <button type="button" onClick={edit}>Edit</button>
        <button type="submit">Submit</button>
      </form>
    );
  }

  const currentStep = steps[stepIdx];
  return (
    <form onSubmit={stepIdx === steps.length - 1 ? gotoReview : (e) => { e.preventDefault(); next(); }}>
      <h3>{form.name} (Step {stepIdx + 1} of {steps.length})</h3>
      {currentStep.fields.map((field) => (
        <div key={field.name}>
          <label>{field.label || field.name}</label>
          <input
            name={field.name}
            type={field.type}
            value={values[field.name] || ""}
            onChange={handleChange}
          />
        </div>
      ))}
      {stepIdx > 0 && <button type="button" onClick={prev}>Back</button>}
      <button type="submit">{stepIdx === steps.length - 1 ? "Review" : "Next"}</button>
      {offline && <span style={{color:"orange"}}>Offline mode</span>}
    </form>
  );
}
EOF

# 4. User dashboard: lists forms, opens forms, shows previous submissions (no analytics)
mkdir -p src/pages/user
cat > src/pages/user/UserDashboard.js <<'EOF'
import React, { useEffect, useState } from "react";
import MultiStepDynamicForm from "../../pwa/MultiStepDynamicForm";
import { cacheForm, getCachedForm, getAllSubmissions, clearSubmissions } from "../../pwa/formCache";

export default function UserDashboard({ user }) {
  const [forms, setForms] = useState([]);
  const [submissions, setSubmissions] = useState([]);
  const [activeForm, setActiveForm] = useState(null);
  const [formStatus, setFormStatus] = useState("");
  const [offline, setOffline] = useState(!navigator.onLine);

  useEffect(() => {
    const updateOnline = () => setOffline(!navigator.onLine);
    window.addEventListener("online", updateOnline);
    window.addEventListener("offline", updateOnline);

    async function fetchForms() {
      if (navigator.onLine) {
        const res = await fetch("/api/forms/");
        const data = await res.json();
        setForms(data);
        data.forEach(cacheForm);
      } else {
        // Optionally implement: fetch all cached forms for offline dashboard
        setForms([]); // Placeholder, can add offline forms loader
      }
    }
    async function fetchSubs() {
      if (navigator.onLine) {
        const res = await fetch("/api/forms/submissions/?user=" + user.id);
        setSubmissions(await res.json());
      } else {
        setSubmissions(await getAllSubmissions());
      }
    }
    fetchForms(); fetchSubs();

    if (navigator.onLine) syncCachedSubmissions();

    return () => {
      window.removeEventListener("online", updateOnline);
      window.removeEventListener("offline", updateOnline);
    };
  }, [user]);

  const openForm = async (form) => {
    if (navigator.onLine) {
      const res = await fetch(`/api/forms/${form.id}/`);
      const detail = await res.json();
      setActiveForm(detail);
    } else {
      const cached = await getCachedForm(form.id);
      setActiveForm(cached || form);
    }
    setFormStatus("");
  };

  async function syncCachedSubmissions() {
    const cached = await getAllSubmissions();
    if (!cached.length) return;
    try {
      await fetch("/api/forms/submit/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cached)
      });
      await clearSubmissions();
    } catch {}
  }

  if (activeForm) {
    return (
      <div>
        <button onClick={() => setActiveForm(null)}>Back to Dashboard</button>
        <MultiStepDynamicForm
          form={activeForm}
          onComplete={msg => { setActiveForm(null); setFormStatus(msg); }}
          offline={offline}
        />
        {formStatus && <div>{formStatus}</div>}
      </div>
    );
  }

  return (
    <div>
      <h2>Available Forms</h2>
      <table>
        <thead>
          <tr><th>Name</th><th>Description</th><th>Open</th></tr>
        </thead>
        <tbody>
          {forms.map(f => (
            <tr key={f.id}>
              <td>{f.name}</td>
              <td>{f.description}</td>
              <td><button onClick={() => openForm(f)}>Open</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Your Submitted Forms</h2>
      <table>
        <thead>
          <tr><th>Form</th><th>Submitted</th><th>Status</th></tr>
        </thead>
        <tbody>
          {submissions.map(s => (
            <tr key={s.id}>
              <td>{s.form_name || s.form}</td>
              <td>{(new Date(s.submitted_at)).toLocaleString()}</td>
              <td>{s.status || "Submitted"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {offline && <div style={{ color: "orange" }}>Offline mode</div>}
    </div>
  );
}
EOF

cat > src/pages/user/index.js <<'EOF'
export { default as UserDashboard } from "./UserDashboard";
EOF

cd ..

echo "==> MASTER UPGRADE COMPLETE: Backend and frontend are now upgraded to the latest enterprise PWA and API features."