import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { MessageCircle, UserCheck, FileCheck } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

export function CollaborationPage() {
  const qc = useQueryClient();
  const [commentText, setCommentText] = useState("");
  const [targetId, setTargetId] = useState("finding-1");

  const { data: assignments } = useQuery({
    queryKey: ["assignments", ""],
    queryFn: () => api.getAssignments(),
  });

  const { data: reviews } = useQuery({
    queryKey: ["reviews", ""],
    queryFn: () => api.getEvidenceReviews(),
  });

  const addCommentMut = useMutation({
    mutationFn: () =>
      api.addCollaborationComment({
        target_id: targetId,
        target_type: "finding",
        author: "user",
        content: commentText,
      }),
    onSuccess: () => {
      toast.success("Comment added");
      setCommentText("");
    },
  });

  const approveReviewMut = useMutation({
    mutationFn: (id: string) => api.approveEvidenceReview(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["reviews"] });
      toast.success("Review approved");
    },
  });

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Collaboration</h1>
        <p className="text-muted-foreground">
          Comments, assignments, evidence reviews, and team workflows
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-blue-500">
            <MessageCircle className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">-</p>
          <p className="text-xs text-muted-foreground">Comments</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-yellow-500">
            <UserCheck className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">
            {assignments?.length ?? 0}
          </p>
          <p className="text-xs text-muted-foreground">Assignments</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-green-500">
            <FileCheck className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">
            {reviews?.length ?? 0}
          </p>
          <p className="text-xs text-muted-foreground">Reviews</p>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 font-medium">Add Comment</h2>
          <div className="flex gap-2">
            <input
              type="text"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              placeholder="Target ID"
              className="w-32 rounded border bg-background px-2 py-1 text-xs"
            />
            <input
              type="text"
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Write a comment..."
              className="flex-1 rounded border bg-background px-2 py-1 text-sm"
            />
            <Button
              size="sm"
              onClick={() => addCommentMut.mutate()}
              disabled={!commentText}
            >
              Send
            </Button>
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 font-medium">Evidence Reviews</h2>
          {(!reviews || reviews.length === 0) && (
            <p className="text-sm text-muted-foreground">
              No pending reviews
            </p>
          )}
          <div className="space-y-2">
            {reviews?.map((review) => (
              <div
                key={review.id}
                className="rounded bg-muted/50 p-3"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm font-medium">
                      Finding: {review.finding_id}
                    </span>
                    <Badge
                      variant={
                        review.status === "approved"
                          ? "default"
                          : review.status === "rejected"
                            ? "destructive"
                            : "secondary"
                      }
                      className="ml-2 text-xs"
                    >
                      {review.status}
                    </Badge>
                  </div>
                  {review.status === "pending" && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => approveReviewMut.mutate(review.id)}
                    >
                      Approve
                    </Button>
                  )}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  Reviewer: {review.reviewer}
                </p>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
